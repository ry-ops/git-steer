/**
 * Shared concurrency limiters for GitHub API requests.
 *
 * GitHub's secondary rate limits fire when too many requests arrive in
 * a short window — the limit is not published but write bursts are the
 * primary trigger. These caps keep git-steer well inside safe territory
 * while still parallelising work that benefits from it.
 *
 * Caps (conservative, validated against GitHub's abuse detection guidance):
 *   writeLimit  — 2 concurrent  (mutations: blobs, issues, PRs, workflow dispatches)
 *   readLimit   — 8 concurrent  (reads: alert scans, file fetches, list endpoints)
 *   searchLimit — 1 concurrent  (Search API: 10 req/min secondary limit)
 */

import pLimit from 'p-limit';

/** For write operations: blob creation, issue/PR creation, workflow dispatch. */
export const writeLimit = pLimit(2);

/** For read operations: security scans, file reads, list endpoints. */
export const readLimit = pLimit(8);

/** For Search API calls (10 req/min secondary limit — keep strictly serial). */
export const searchLimit = pLimit(1);
