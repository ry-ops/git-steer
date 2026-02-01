/**
 * Keychain service for macOS
 * 
 * Stores all sensitive data (GitHub App credentials) in the macOS Keychain.
 * This is the ONLY persistent local storage git-steer uses.
 */

import keytar from 'keytar';

const SERVICE_NAME = 'git-steer';

export class KeychainService {
  /**
   * Store a value in the Keychain
   */
  async set(key: string, value: string): Promise<void> {
    await keytar.setPassword(SERVICE_NAME, key, value);
  }

  /**
   * Retrieve a value from the Keychain
   */
  async get(key: string): Promise<string | null> {
    return keytar.getPassword(SERVICE_NAME, key);
  }

  /**
   * Delete a value from the Keychain
   */
  async delete(key: string): Promise<boolean> {
    return keytar.deletePassword(SERVICE_NAME, key);
  }

  /**
   * Check if a key exists
   */
  async has(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  /**
   * Clear all git-steer credentials
   */
  async clear(): Promise<void> {
    const keys = [
      'git-steer-app-id',
      'git-steer-installation-id',
      'git-steer-private-key',
      'git-steer-state-repo',
      'git-steer-version',
    ];

    for (const key of keys) {
      await this.delete(key);
    }
  }

  /**
   * Get all stored credentials (for debugging, redacted)
   */
  async list(): Promise<Record<string, boolean>> {
    const keys = [
      'git-steer-app-id',
      'git-steer-installation-id',
      'git-steer-private-key',
      'git-steer-state-repo',
      'git-steer-version',
    ];

    const result: Record<string, boolean> = {};
    for (const key of keys) {
      result[key] = await this.has(key);
    }
    return result;
  }
}
