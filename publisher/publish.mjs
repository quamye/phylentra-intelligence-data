import fs from 'node:fs';
import path from 'node:path';
import {
  acceptEpssPage,
  canonical,
  decidePublication,
  extractCveIds,
  feedUpdated,
  finishEpssQuery,
  generationId,
  packBatches,
  slimKev,
} from './decide.mjs';

const ROOT = path.resolve(process.env.SNAPSHOT_ROOT ?? path.join(process.cwd(), 'data'));
const USER_AGENT = 'PHYLENTRA-prototype/1.0 (enrichment snapshot publisher)';
const HOSTS = {
  kev: new Set(['www.cisa.gov']),
  epss: new Set(['api.first.org']),
  feed: new Set(['www.cyber.gc.ca', 'cyber.gc.ca']),
};
const URLS = {
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  epss: 'https://api.first.org/data/v1/epss',
  feed: 'https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en',
};

const fetchImpl = globalThis.fetch;

async function main() {
  const now = new Date();
  const attemptedAt = now.toISOString();
  const generation = generationId(now);
  const previous = readPrevious();
  const kev = await loadKev();
  const epss = await loadEpss();
  const decision = decidePublication({ previous, generation, attemptedAt, kev, epss, now });
  for (const [filePath, body] of Object.entries(decision.files)) {
    const target = path.resolve(ROOT, path.relative('data', filePath));
    if (!target.startsWith(ROOT)) throw new Error('A snapshot path escaped the data directory.');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, canonical(body));
  }
  process.stdout.write(`generation ${generation}\n`);
}

function readPrevious() {
  const manifestPath = path.join(ROOT, 'manifest.json');
  if (!fs.existsSync(manifestPath)) return null;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const kevFile = manifest?.kev?.payload ? path.join(ROOT, path.relative('data', manifest.kev.payload)) : null;
  const epssFile = manifest?.epss?.payload ? path.join(ROOT, path.relative('data', manifest.epss.payload)) : null;
  const kevBody = kevFile && fs.existsSync(kevFile) ? JSON.parse(fs.readFileSync(kevFile, 'utf8')) : null;
  const epssBody = epssFile && fs.existsSync(epssFile) ? JSON.parse(fs.readFileSync(epssFile, 'utf8')) : null;
  return {
    manifest,
    kevCanonical: kevBody ? canonical({
      catalogVersion: kevBody.catalogVersion,
      dateReleased: kevBody.dateReleased,
      byCve: kevBody.byCve,
    }) : null,
    epssRecords: epssBody?.records ?? {},
  };
}

async function loadKev() {
  try {
    const text = await getText(URLS.kev, 'kev', 'application/json');
    return { ok: true, slim: slimKev(JSON.parse(text)) };
  } catch {
    return { ok: false };
  }
}

async function loadEpss() {
  try {
    const xml = await getText(URLS.feed, 'feed', 'application/atom+xml, application/xml, text/xml');
    if (!/<feed[\s>]|<entry[\s>]/i.test(xml)) return { ok: false };
    const requested = extractCveIds(xml);
    const input = { feedUrl: URLS.feed, feedUpdated: feedUpdated(xml), cveCount: requested.length };
    const scored = [];
    const noRecord = [];
    let failed = false;
    for (const batch of packBatches(requested)) {
      const result = await lookupBatch(batch);
      if (!result.ok) {
        failed = true;
        continue;
      }
      scored.push(...result.scored);
      noRecord.push(...result.noRecord);
    }
    if (requested.length === 0) return { ok: true, requested, scored, noRecord, input };
    if (failed && scored.length === 0 && noRecord.length === 0) return { ok: false };
    return { ok: true, requested, scored, noRecord, input };
  } catch {
    return { ok: false };
  }
}

async function lookupBatch(batch) {
  const rows = [];
  let offset = 0;
  let total = null;
  for (let page = 0; page < 20; page += 1) {
    const url = new URL(URLS.epss);
    url.searchParams.set('cve', batch.join(','));
    url.searchParams.set('limit', '100');
    url.searchParams.set('offset', String(offset));
    let parsed;
    try {
      parsed = JSON.parse(await getText(url.toString(), 'epss', 'application/json'));
    } catch {
      return { ok: false };
    }
    const accepted = acceptEpssPage(batch, parsed, offset);
    if (!accepted.ok) return { ok: false };
    rows.push(...accepted.rows);
    total = accepted.total;
    offset = accepted.nextOffset;
    if (accepted.complete) break;
  }
  if (total === null || offset < total) return { ok: false };
  const finished = finishEpssQuery(batch, rows);
  return finished.ok ? finished : { ok: false };
}

async function getText(urlString, hostGroup, accept) {
  let current = new URL(urlString);
  for (let redirect = 0; redirect <= 3; redirect += 1) {
    if (!HOSTS[hostGroup].has(current.hostname)) throw new Error('host');
    let response;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      response = await fetchImpl(current.toString(), {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        signal: AbortSignal.timeout(20000),
        headers: { accept, 'user-agent': USER_AGENT },
      });
      if (response.status !== 429 && response.status !== 503) break;
      if (attempt === 3) throw new Error('status');
      const retryAfter = Number(response.headers.get('retry-after'));
      const wait = Number.isFinite(retryAfter) && retryAfter >= 0 ? Math.min(retryAfter * 1000, 30000) : 2000;
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location || redirect === 3) throw new Error('redirect');
      current = new URL(location, current);
      continue;
    }
    if (response.status !== 200) throw new Error('status');
    const advertised = Number(response.headers.get('content-length'));
    if (Number.isFinite(advertised) && advertised > 8_000_000) throw new Error('size');
    const text = await response.text();
    if (text.length > 8_000_000) throw new Error('size');
    return text;
  }
  throw new Error('redirect');
}

main().catch((error) => {
  process.stderr.write('publisher failed before it could write a manifest\n');
  process.stderr.write(error instanceof Error ? error.name : 'Error');
  process.stderr.write('\n');
  process.exitCode = 1;
});
