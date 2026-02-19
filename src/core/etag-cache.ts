/**
 * ETag cache for GitHub Contents API GET requests.
 *
 * GitHub returns an ETag header on every GET /repos/{owner}/{repo}/contents/{path}
 * response. On the next request we send If-None-Match: <etag>. If the file
 * hasn't changed GitHub responds 304 Not Modified (no body, counts at reduced
 * rate-limit weight). We return the cached body instead of re-downloading.
 *
 * Octokit throws a RequestError with status 304 rather than returning normally,
 * so callers must catch that error and call hit() to retrieve the cached value.
 *
 * Persistence: the map is serialised to/from state/cache.json under the key
 * "_etags" by StateManager. Call load() after state loads and snapshot() before
 * state saves.
 */

export interface ETagEntry {
  etag: string;
  content: string;
  sha: string;
}

export class ETagCache {
  private cache = new Map<string, ETagEntry>();

  /** Stable cache key for a file GET. ref is optional (omit for default branch). */
  static key(owner: string, repo: string, path: string, ref?: string): string {
    return ref
      ? `${owner}/${repo}/${path}?ref=${ref}`
      : `${owner}/${repo}/${path}`;
  }

  /** Return the stored ETag for a key, or undefined if not cached. */
  getETag(key: string): string | undefined {
    return this.cache.get(key)?.etag;
  }

  /**
   * Store a fresh response.
   * @param key   Cache key from ETagCache.key()
   * @param etag  Value of the ETag response header (already normalised — no quotes)
   * @param content Decoded UTF-8 file content
   * @param sha   Git blob SHA from response body
   */
  set(key: string, etag: string, content: string, sha: string): void {
    this.cache.set(key, { etag, content, sha });
  }

  /**
   * Return cached content after a 304 hit, or null if not in cache.
   * (The caller should only reach this path after catching a 304 RequestError.)
   */
  hit(key: string): { content: string; sha: string } | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    return { content: entry.content, sha: entry.sha };
  }

  /** Invalidate a single entry (e.g. after a successful PUT to the same path). */
  invalidate(key: string): void {
    this.cache.delete(key);
  }

  /** Serialise to a plain object for persistence in cache.json. */
  snapshot(): Record<string, ETagEntry> {
    return Object.fromEntries(this.cache.entries());
  }

  /** Restore from a plain object loaded from cache.json. */
  load(data: Record<string, ETagEntry>): void {
    this.cache.clear();
    for (const [key, entry] of Object.entries(data)) {
      if (entry?.etag && entry?.content !== undefined && entry?.sha) {
        this.cache.set(key, entry);
      }
    }
  }

  /** Number of cached entries (useful for steer_status diagnostics). */
  size(): number {
    return this.cache.size;
  }
}

/** Singleton used by GitHubClient. StateManager populates it after load(). */
export const etagCache = new ETagCache();
