export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
export const BATCH_SIZE = 100;
export const CVE_PARAM_LIMIT = 2000;
export const FETCH_STALE_MS = 36 * 60 * 60 * 1000;
export const SCORE_DATE_SLACK_DAYS = 1;

export const ATTRIBUTION = {
  kev: 'CISA Known Exploited Vulnerabilities catalog, redistributed under CC0 1.0. Date added is the catalog date, not an exploitation-event date. This project does not use CISA or DHS marks and is not endorsed by CISA or DHS.',
  epss: 'EPSS probability and percentile are FIRST scores (https://www.first.org/epss). Cite Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, and Idris Adjerid (2021), Exploit Prediction Scoring System, Digital Threats: Research and Practice, 2(3). A later fetch does not change the score date.',
};

export function generationId(now) {
  const id = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  if (!/^\d{8}T\d{6}Z$/.test(id)) throw new Error('The generation id was not a UTC timestamp.');
  return id;
}

export function normalizeCves(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const id = String(value ?? '').trim().toUpperCase();
    if (!CVE_PATTERN.test(id) || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  out.sort();
  return out;
}

export function extractCveIds(xml) {
  return normalizeCves(String(xml).match(/CVE-\d{4}-\d{4,}/gi) ?? []);
}

export function feedUpdated(xml) {
  const match = String(xml).match(/<updated>([^<]*)<\/updated>/i);
  if (!match) return null;
  const value = match[1].trim();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return new Date(parsed).toISOString();
}

export function packBatches(cves) {
  const batches = [];
  let current = [];
  let length = 0;
  for (const cve of normalizeCves(cves)) {
    const nextLength = current.length === 0 ? cve.length : length + 1 + cve.length;
    if (current.length > 0 && (current.length >= BATCH_SIZE || nextLength > CVE_PARAM_LIMIT)) {
      batches.push(current);
      current = [];
      length = 0;
    }
    current.push(cve);
    length = current.length === 1 ? cve.length : length + 1 + cve.length;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

export function scoreDateStale(scoreDate, now) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(scoreDate ?? '')) return true;
  const score = Date.parse(`${scoreDate}T00:00:00Z`);
  if (!Number.isFinite(score)) return true;
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const ageDays = Math.floor((today - score) / 86400000);
  return ageDays > SCORE_DATE_SLACK_DAYS;
}

export function fetchStale(fetchedAt, now) {
  const parsed = Date.parse(fetchedAt ?? '');
  if (!Number.isFinite(parsed)) return true;
  return now.getTime() - parsed > FETCH_STALE_MS;
}

function dateOnly(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value ?? '');
}

function finiteUnit(value) {
  const number = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(number) && number >= 0 && number <= 1 ? number : null;
}

export function acceptEpssPage(requested, page, offset) {
  const requestedSet = new Set(requested);
  if (!page || page.status !== 'OK' || !Array.isArray(page.data) || !Number.isInteger(page.total) || page.total < 0) {
    return { ok: false, reason: 'malformed' };
  }
  if (!Number.isInteger(page.limit) || page.limit < 1 || !Number.isInteger(page.offset) || page.offset !== offset) {
    return { ok: false, reason: 'page' };
  }
  const rows = [];
  const seen = new Set();
  for (const row of page.data) {
    const cve = String(row?.cve ?? '').toUpperCase();
    if (!requestedSet.has(cve) || seen.has(cve)) return { ok: false, reason: 'identity' };
    const epss = finiteUnit(row.epss);
    const percentile = finiteUnit(row.percentile);
    if (epss === null || percentile === null || !dateOnly(row.date)) return { ok: false, reason: 'value' };
    seen.add(cve);
    rows.push({ cve, epss, percentile, scoreDate: row.date });
  }
  const nextOffset = offset + rows.length;
  if (rows.length === 0 && nextOffset < page.total) return { ok: false, reason: 'incomplete' };
  if (nextOffset > page.total) return { ok: false, reason: 'incomplete' };
  return { ok: true, rows, nextOffset, complete: nextOffset >= page.total, total: page.total };
}

export function finishEpssQuery(requested, rows) {
  const found = new Map(rows.map((row) => [row.cve, row]));
  if (found.size !== rows.length) return { ok: false, reason: 'identity' };
  const scored = [];
  const noRecord = [];
  for (const cve of requested) {
    const row = found.get(cve);
    if (row) scored.push(row);
    else noRecord.push(cve);
  }
  return { ok: true, scored, noRecord };
}

export function slimKev(document) {
  if (!document || !Array.isArray(document.vulnerabilities) || !Number.isInteger(document.count)) {
    throw new Error('KEV catalog was not a counted list.');
  }
  if (document.count !== document.vulnerabilities.length) {
    throw new Error('KEV count did not match the entries.');
  }
  if (typeof document.catalogVersion !== 'string' || typeof document.dateReleased !== 'string') {
    throw new Error('KEV catalog version was missing.');
  }
  if (!Number.isFinite(Date.parse(document.dateReleased))) {
    throw new Error('KEV dateReleased was not a date.');
  }
  const byCve = {};
  for (const entry of document.vulnerabilities) {
    const cve = String(entry?.cveID ?? '').toUpperCase();
    if (!CVE_PATTERN.test(cve) || byCve[cve]) throw new Error('KEV identity was not unique.');
    if (!dateOnly(entry.dateAdded)) throw new Error('KEV dateAdded was not a calendar date.');
    if (entry.knownRansomwareCampaignUse !== 'Known' && entry.knownRansomwareCampaignUse !== 'Unknown') {
      throw new Error('KEV ransomware field was not Known or Unknown.');
    }
    byCve[cve] = {
      dateAdded: entry.dateAdded,
      knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
    };
  }
  return {
    catalogVersion: document.catalogVersion,
    dateReleased: new Date(document.dateReleased).toISOString(),
    byCve,
  };
}

export function canonical(value) {
  return `${JSON.stringify(sortKeys(value))}\n`;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortKeys(value[key])]));
  }
  return value;
}

function coverageOf(records, requested) {
  const coverage = { requested: requested.length, scored: 0, noRecord: 0, failed: 0, staleRetained: 0 };
  for (const cve of requested) {
    const outcome = records[cve]?.outcome;
    if (outcome === 'scored') coverage.scored += 1;
    else if (outcome === 'no-record') coverage.noRecord += 1;
    else if (outcome === 'stale') coverage.staleRetained += 1;
    else coverage.failed += 1;
  }
  return coverage;
}

function previousEpssRecords(previous) {
  return previous?.epssRecords ?? {};
}

export function decidePublication({ previous, generation, attemptedAt, kev, epss, now }) {
  const kevPayload = publishKev(previous, generation, attemptedAt, kev);
  const epssPayload = publishEpss(previous, generation, attemptedAt, epss, now);
  const manifest = {
    schemaVersion: 1,
    generationId: generation,
    attribution: ATTRIBUTION,
    kev: kevPayload.source,
    epss: epssPayload.source,
  };
  const files = {};
  if (kevPayload.file) files[kevPayload.file.path] = kevPayload.file.body;
  if (epssPayload.file) files[epssPayload.file.path] = epssPayload.file.body;
  files['data/manifest.json'] = manifest;
  return { manifest, files };
}

function publishKev(previous, generation, attemptedAt, kev) {
  const prior = previous?.manifest?.kev ?? null;
  if (!kev.ok) {
    return {
      source: {
        outcome: 'failed',
        attemptedAt,
        fetchedAt: prior?.fetchedAt ?? null,
        sourceDate: prior?.sourceDate ?? null,
        catalogVersion: prior?.catalogVersion ?? null,
        payload: prior?.payload ?? null,
        entryCount: prior?.entryCount ?? null,
      },
      file: null,
    };
  }
  const slim = {
    catalogVersion: kev.slim.catalogVersion,
    dateReleased: kev.slim.dateReleased,
    byCve: kev.slim.byCve,
  };
  const unchanged = previous?.kevCanonical === canonical(slim) && prior?.payload;
  const path = unchanged ? prior.payload : `data/generations/${generation}/kev.json`;
  return {
    source: {
      outcome: 'succeeded',
      attemptedAt,
      fetchedAt: attemptedAt,
      sourceDate: kev.slim.dateReleased,
      catalogVersion: kev.slim.catalogVersion,
      payload: path,
      entryCount: Object.keys(kev.slim.byCve).length,
    },
    file: unchanged ? null : {
      path,
      body: { schemaVersion: 1, generationId: generation, ...slim },
    },
  };
}

function publishEpss(previous, generation, attemptedAt, epss, now) {
  const priorRecords = previousEpssRecords(previous);
  const priorSource = previous?.manifest?.epss ?? null;
  if (!epss.ok) {
    return {
      source: {
        outcome: 'failed',
        attemptedAt,
        fetchedAt: priorSource?.fetchedAt ?? null,
        sourceDate: priorSource?.sourceDate ?? null,
        payload: priorSource?.payload ?? null,
        input: priorSource?.input ?? null,
        coverage: priorSource?.coverage ?? null,
      },
      file: null,
    };
  }
  const records = {};
  for (const cve of epss.requested) {
    const success = epss.scored.find((row) => row.cve === cve);
    const absent = epss.noRecord.includes(cve);
    const prior = priorRecords[cve];
    if (success) {
      const unchanged = prior && prior.outcome === 'scored' && prior.scoreDate === success.scoreDate && prior.epss === success.epss && prior.percentile === success.percentile;
      records[cve] = {
        outcome: 'scored',
        epss: success.epss,
        percentile: success.percentile,
        scoreDate: success.scoreDate,
        fetchedAt: unchanged ? prior.fetchedAt : attemptedAt,
        attemptedAt,
        scoreDateStale: scoreDateStale(success.scoreDate, now),
      };
    } else if (absent) {
      records[cve] = {
        outcome: 'no-record',
        epss: null,
        percentile: null,
        scoreDate: null,
        fetchedAt: attemptedAt,
        attemptedAt,
        scoreDateStale: false,
      };
    } else if (prior && (prior.outcome === 'scored' || prior.outcome === 'no-record' || prior.outcome === 'stale')) {
      records[cve] = {
        ...prior,
        outcome: 'stale',
        attemptedAt,
        fetchedAt: prior.fetchedAt,
        scoreDate: prior.scoreDate,
        scoreDateStale: prior.scoreDate ? scoreDateStale(prior.scoreDate, now) : false,
      };
    } else {
      records[cve] = {
        outcome: 'failed',
        epss: null,
        percentile: null,
        scoreDate: null,
        fetchedAt: null,
        attemptedAt,
        scoreDateStale: false,
      };
    }
  }
  const coverage = coverageOf(records, epss.requested);
  const outcome = coverage.failed + coverage.staleRetained > 0 ? 'partial' : 'succeeded';
  const body = {
    schemaVersion: 1,
    generationId: generation,
    requested: epss.requested,
    records,
  };
  const path = `data/generations/${generation}/epss.json`;
  const newestScoreDate = epss.scored.map((row) => row.scoreDate).sort().at(-1) ?? priorSource?.sourceDate ?? null;
  return {
    source: {
      outcome,
      attemptedAt,
      fetchedAt: attemptedAt,
      sourceDate: newestScoreDate,
      payload: path,
      input: epss.input,
      coverage,
    },
    file: { path, body },
  };
}
