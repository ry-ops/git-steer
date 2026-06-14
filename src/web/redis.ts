/**
 * Redis client for the git-steer web layer.
 *
 * Provides a singleton Redis connection and key namespace helpers
 * for scan lifecycle, VEX entries, SBOM snapshots, trends, and auto-scan config.
 */

import { createClient } from 'redis';

let client: ReturnType<typeof createClient> | null = null;

export async function getRedis() {
  if (!client) {
    const url = process.env.REDIS_URL ?? 'redis://redis-master.fabric-sdk:6379';
    client = createClient({ url });
    client.on('error', (err) => console.warn('[redis]', err.message));
    await client.connect();
  }
  return client;
}

export const KEYS = {
  scan: (id: string) => `gitsteer:scan:${id}`,
  scanHistory: (repo: string) => `gitsteer:scans:${repo.replace('/', ':')}`,
  scanLatest: (repo: string) => `gitsteer:scan:latest:${repo.replace('/', ':')}`,
  vex: (repo: string, cveId: string) => `gitsteer:vex:${repo.replace('/', ':')}:${cveId}`,
  vexList: (repo: string) => `gitsteer:vex:${repo.replace('/', ':')}`,
  vexLedger: (repo: string) => `gitsteer:vexledger:${repo.replace('/', ':')}`,
  sbom: (repo: string) => `gitsteer:sbom:${repo.replace('/', ':')}`,
  trend: (repo: string) => `gitsteer:trend:${repo.replace('/', ':')}`,
  autoScan: (repo: string) => `gitsteer:autoscan:${repo.replace('/', ':')}`,
};
