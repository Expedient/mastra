import type { IMastraLogger } from '../logger';

export interface LicenseValidationSuccess {
  valid: true;
  entitlements: string[];
  planTier: string;
  expiresAt: string | null;
  leaseTtlSeconds: number;
}
export interface LicenseValidationError {
  valid: false;
  code: 'INVALID_KEY' | 'LICENSE_EXPIRED' | 'LICENSE_REVOKED' | 'RATE_LIMITED';
  reason: string;
}
export type LicenseValidationResponse = LicenseValidationSuccess | LicenseValidationError;
export type LicenseMode = 'open-source';
export type LicenseStatus = 'valid';
export interface LicenseSnapshot {
  mode: LicenseMode;
  status: LicenseStatus;
  entitlements: null;
  planTier: null;
  expiresAt: null;
}

/**
 * Network-free compatibility surface for applications that inspect the open-source runtime.
 * It never reads a key, schedules background work, or grants commercial entitlements.
 */
export class LicenseClient {
  private static instance: LicenseClient | undefined;
  private constructor(_logger?: IMastraLogger) {}
  static getInstance(logger?: IMastraLogger): LicenseClient {
    LicenseClient.instance ??= new LicenseClient(logger);
    return LicenseClient.instance;
  }
  static resetInstance(): void {
    LicenseClient.instance = undefined;
  }
  async validate(): Promise<boolean> {
    return true;
  }
  hasFeature(_featureName: string): boolean {
    return false;
  }
  getEntitlements(): null {
    return null;
  }
  getSnapshot(): LicenseSnapshot {
    return { mode: 'open-source', status: 'valid', entitlements: null, planTier: null, expiresAt: null };
  }
}
