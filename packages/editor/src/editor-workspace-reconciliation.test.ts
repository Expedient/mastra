import { describe, expect, it } from 'vitest';
import { snapshotsMatch } from './snapshots-match';

// =============================================================================
// snapshotsMatch — unit tests
// =============================================================================

describe('snapshotsMatch', () => {
  it('returns true for identical snapshots', () => {
    const snapshot = { name: 'ws', filesystem: { provider: 'local', config: { basePath: '/tmp' } } };
    expect(snapshotsMatch(snapshot, snapshot)).toBe(true);
  });

  it('returns true when both have only name', () => {
    expect(snapshotsMatch({ name: 'ws' }, { name: 'ws' })).toBe(true);
  });

  it('returns false when names differ', () => {
    expect(snapshotsMatch({ name: 'a' }, { name: 'b' })).toBe(false);
  });

  it('returns false when one has filesystem and other does not', () => {
    const a = { name: 'ws' };
    const b = { name: 'ws', filesystem: { provider: 'local', config: {} } };
    expect(snapshotsMatch(a, b)).toBe(false);
  });

  it('returns false when filesystem config differs', () => {
    const a = { name: 'ws', filesystem: { provider: 'local', config: { basePath: '/a' } } };
    const b = { name: 'ws', filesystem: { provider: 'local', config: { basePath: '/b' } } };
    expect(snapshotsMatch(a, b)).toBe(false);
  });

  it('returns false when filesystem provider differs', () => {
    const a = { name: 'ws', filesystem: { provider: 'local', config: {} } };
    const b = { name: 'ws', filesystem: { provider: 's3', config: {} } };
    expect(snapshotsMatch(a, b)).toBe(false);
  });

  it('returns true when both have undefined optional fields', () => {
    const a = { name: 'ws', description: undefined, sandbox: undefined };
    const b = { name: 'ws' };
    expect(snapshotsMatch(a, b)).toBe(true);
  });

  it('detects sandbox changes', () => {
    const a = { name: 'ws', sandbox: { provider: 'local', config: {} } };
    const b = { name: 'ws', sandbox: { provider: 'e2b', config: {} } };
    expect(snapshotsMatch(a, b)).toBe(false);
  });

  it('detects tools config changes', () => {
    const a = { name: 'ws', tools: { enabled: true } };
    const b = { name: 'ws', tools: { enabled: false } };
    expect(snapshotsMatch(a, b)).toBe(false);
  });

  it('ignores metadata fields not in snapshot keys', () => {
    // snapshotsMatch only compares config fields, not id/metadata/status
    const stored = { name: 'ws', id: 'x', status: 'draft' as const } as any;
    const runtime = { name: 'ws' };
    expect(snapshotsMatch(stored, runtime)).toBe(true);
  });
});
