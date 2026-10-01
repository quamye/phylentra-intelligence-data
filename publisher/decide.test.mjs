import assert from 'node:assert/strict';
import test from 'node:test';
import {
  acceptEpssPage,
  decidePublication,
  extractCveIds,
  fetchStale,
  finishEpssQuery,
  generationId,
  packBatches,
  scoreDateStale,
  slimKev,
} from './decide.mjs';

const now = new Date('2026-10-01T15:17:00.000Z');

test('packs by batch size and the 2000-character parameter limit', () => {
  const wide = Array.from({ length: 120 }, (_, index) => `CVE-2024-${String(10000 + index)}`);
  const batches = packBatches(wide);
  assert.ok(batches.every((batch) => batch.length <= 100));
  assert.ok(batches.every((batch) => batch.join(',').length <= 2000));
  assert.equal(batches.flat().length, 120);
  const longId = `CVE-2024-${'1'.repeat(1990)}`;
  const packed = packBatches([longId, 'CVE-2024-1000', 'CVE-2024-1000']);
  assert.deepEqual(packed, [['CVE-2024-1000'], [longId]]);
});

test('extracts CVE identifiers and ignores advisory prose', () => {
  const xml = '<feed><updated>2026-10-01T12:00:00Z</updated><entry><title>Ignore this title</title><summary>CVE-2024-1234 and cve-2024-1234</summary></entry></feed>';
  assert.deepEqual(extractCveIds(xml), ['CVE-2024-1234']);
});

test('rejects an incomplete EPSS page and does not call the omission a no-record', () => {
  const requested = ['CVE-2024-1000', 'CVE-2024-1001'];
  const incomplete = acceptEpssPage(requested, { status: 'OK', total: 2, offset: 0, limit: 100, data: [] }, 0);
  assert.equal(incomplete.ok, false);
  assert.equal(incomplete.reason, 'incomplete');
  const page = acceptEpssPage(requested, {
    status: 'OK',
    total: 1,
    offset: 0,
    limit: 100,
    data: [{ cve: 'CVE-2024-1000', epss: '0.250000000', percentile: '0.800000000', date: '2026-10-01' }],
  }, 0);
  assert.equal(page.ok, true);
  assert.equal(page.complete, true);
  const finished = finishEpssQuery(requested, page.rows);
  assert.deepEqual(finished.noRecord, ['CVE-2024-1001']);
});

test('rejects a KEV catalog whose count does not match', () => {
  assert.throws(() => slimKev({
    catalogVersion: '2026.10.01',
    dateReleased: '2026-10-01T00:00:00Z',
    count: 2,
    vulnerabilities: [{ cveID: 'CVE-2024-1000', dateAdded: '2026-01-02', knownRansomwareCampaignUse: 'Known' }],
  }));
});

test('keeps an old EPSS score date stale after a newer fetch', () => {
  assert.equal(scoreDateStale('2026-09-20', now), true);
  assert.equal(scoreDateStale('2026-09-30', now), false);
  assert.equal(fetchStale('2026-09-29T15:17:00.000Z', now), true);
  const previous = {
    manifest: {
      kev: { outcome: 'succeeded', attemptedAt: '2026-09-30T15:17:00.000Z', fetchedAt: '2026-09-30T15:17:00.000Z', sourceDate: '2026-09-30T00:00:00.000Z', catalogVersion: '2026.09.30', payload: 'data/generations/20260930T151700Z/kev.json', entryCount: 1 },
      epss: { outcome: 'succeeded', attemptedAt: '2026-09-30T15:17:00.000Z', fetchedAt: '2026-09-30T15:17:00.000Z', sourceDate: '2026-09-20', payload: 'data/generations/20260930T151700Z/epss.json', input: { feedUrl: 'https://www.cyber.gc.ca/feed', feedUpdated: null, cveCount: 1 }, coverage: { requested: 1, scored: 1, noRecord: 0, failed: 0, staleRetained: 0 } },
    },
    epssRecords: {
      'CVE-2024-1000': { outcome: 'scored', epss: 0.2, percentile: 0.7, scoreDate: '2026-09-20', fetchedAt: '2026-09-30T15:17:00.000Z', attemptedAt: '2026-09-30T15:17:00.000Z', scoreDateStale: true },
    },
  };
  const decision = decidePublication({
    previous,
    generation: generationId(now),
    attemptedAt: now.toISOString(),
    now,
    kev: { ok: false },
    epss: {
      ok: true,
      requested: ['CVE-2024-1000'],
      scored: [{ cve: 'CVE-2024-1000', epss: 0.2, percentile: 0.7, scoreDate: '2026-09-20' }],
      noRecord: [],
      input: { feedUrl: 'https://www.cyber.gc.ca/feed', feedUpdated: null, cveCount: 1 },
    },
  });
  const record = decision.files['data/generations/20261001T151700Z/epss.json'].records['CVE-2024-1000'];
  assert.equal(record.scoreDate, '2026-09-20');
  assert.equal(record.fetchedAt, '2026-09-30T15:17:00.000Z');
  assert.equal(record.scoreDateStale, true);
  assert.equal(decision.manifest.kev.payload, previous.manifest.kev.payload);
  assert.equal(decision.manifest.kev.outcome, 'failed');
});

test('a partial EPSS batch keeps the last good row and marks the failure', () => {
  const previous = {
    manifest: { kev: { payload: null, fetchedAt: null, sourceDate: null, catalogVersion: null, entryCount: null }, epss: { payload: 'old', fetchedAt: '2026-09-30T15:17:00.000Z', sourceDate: '2026-09-30', input: null, coverage: null } },
    epssRecords: {
      'CVE-2024-1001': { outcome: 'scored', epss: 0.4, percentile: 0.9, scoreDate: '2026-09-30', fetchedAt: '2026-09-30T15:17:00.000Z', attemptedAt: '2026-09-30T15:17:00.000Z', scoreDateStale: false },
    },
  };
  const decision = decidePublication({
    previous,
    generation: '20261001T151700Z',
    attemptedAt: now.toISOString(),
    now,
    kev: { ok: false },
    epss: {
      ok: true,
      requested: ['CVE-2024-1000', 'CVE-2024-1001', 'CVE-2024-1002'],
      scored: [{ cve: 'CVE-2024-1000', epss: 0.1, percentile: 0.2, scoreDate: '2026-10-01' }],
      noRecord: ['CVE-2024-1002'],
      input: { feedUrl: 'https://www.cyber.gc.ca/feed', feedUpdated: '2026-10-01T12:00:00.000Z', cveCount: 3 },
    },
  });
  const records = decision.files['data/generations/20261001T151700Z/epss.json'].records;
  assert.equal(records['CVE-2024-1000'].outcome, 'scored');
  assert.equal(records['CVE-2024-1001'].outcome, 'stale');
  assert.equal(records['CVE-2024-1001'].fetchedAt, '2026-09-30T15:17:00.000Z');
  assert.equal(records['CVE-2024-1002'].outcome, 'no-record');
  assert.equal(decision.manifest.epss.outcome, 'partial');
  assert.equal(decision.manifest.epss.coverage.failed, 0);
  assert.equal(decision.manifest.epss.coverage.staleRetained, 1);
});

test('complete failure does not replace the last payload', () => {
  const previous = {
    manifest: {
      kev: { outcome: 'succeeded', payload: 'data/generations/old/kev.json', fetchedAt: '2026-09-30T15:17:00.000Z', sourceDate: '2026-09-30T00:00:00.000Z', catalogVersion: '2026.09.30', entryCount: 1 },
      epss: { outcome: 'succeeded', payload: 'data/generations/old/epss.json', fetchedAt: '2026-09-30T15:17:00.000Z', sourceDate: '2026-09-30', input: { feedUrl: 'https://www.cyber.gc.ca/feed', feedUpdated: null, cveCount: 1 }, coverage: { requested: 1, scored: 1, noRecord: 0, failed: 0, staleRetained: 0 } },
    },
    epssRecords: {},
  };
  const decision = decidePublication({
    previous,
    generation: '20261001T151700Z',
    attemptedAt: now.toISOString(),
    now,
    kev: { ok: false },
    epss: { ok: false },
  });
  assert.equal(decision.manifest.kev.payload, 'data/generations/old/kev.json');
  assert.equal(decision.manifest.epss.payload, 'data/generations/old/epss.json');
  assert.equal(Object.keys(decision.files).length, 1);
  assert.equal(decision.files['data/manifest.json'].generationId, '20261001T151700Z');
});

test('generation ids are timestamps, not upstream text', () => {
  assert.equal(generationId(now), '20261001T151700Z');
  assert.throws(() => generationId(new Date('invalid')));
});
