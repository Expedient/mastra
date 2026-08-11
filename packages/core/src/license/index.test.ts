import { afterEach, describe, expect, it, vi } from 'vitest';

import { Mastra } from '../mastra';
import { LicenseClient } from './index';

describe('open-source license compatibility surface', () => {
  afterEach(() => {
    LicenseClient.resetInstance();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it('cannot turn license environment variables into network calls, timers, or grants', async () => {
    vi.stubEnv('MASTRA_LICENSE_KEY', 'attacker-controlled-license-key');
    vi.stubEnv('MASTRA_EE_LICENSE', 'attacker-controlled-ee-license');
    const fetch = vi.spyOn(globalThis, 'fetch');
    const timeout = vi.spyOn(globalThis, 'setTimeout');
    const interval = vi.spyOn(globalThis, 'setInterval');

    const client = LicenseClient.getInstance();
    await expect(client.validate()).resolves.toBe(true);

    expect(fetch).not.toHaveBeenCalled();
    expect(timeout).not.toHaveBeenCalled();
    expect(interval).not.toHaveBeenCalled();
    expect(client.hasFeature('enterprise')).toBe(false);
    expect(client.getEntitlements()).toBeNull();
    expect(client.getSnapshot()).toEqual({
      mode: 'open-source',
      status: 'valid',
      entitlements: null,
      planTier: null,
      expiresAt: null,
    });
  });

  it('does not start license validation during Mastra construction even when hostile env vars are present', () => {
    vi.stubEnv('MASTRA_LICENSE_KEY', 'attacker-controlled-license-key');
    vi.stubEnv('MASTRA_EE_LICENSE', 'attacker-controlled-ee-license');
    const validate = vi.spyOn(LicenseClient.prototype, 'validate');

    new Mastra({ logger: false });

    expect(validate).not.toHaveBeenCalled();
  });
});
