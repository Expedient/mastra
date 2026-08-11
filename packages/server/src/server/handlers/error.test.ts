import { ErrorCategory, ErrorDomain, MastraError } from '@mastra/core/error';
import { describe, expect, it } from 'vitest';

import { HTTPException } from '../http-exception';
import { handleError } from './error';

describe('handleError', () => {
  it('uses an explicit status from MastraError details', () => {
    const err = new MastraError({
      id: 'OBSERVATIONAL_MEMORY_THREAD_ID_REQUIRED',
      domain: ErrorDomain.MASTRA_MEMORY,
      category: ErrorCategory.USER,
      text: 'ObservationalMemory requires a threadId',
      details: { status: 400 },
    });

    expect(() => handleError(err, 'default')).toThrow(
      expect.objectContaining({
        status: 400,
        message: 'ObservationalMemory requires a threadId',
      }),
    );
  });

  describe('MODEL_NOT_ALLOWED handling', () => {
    function makeModelNotAllowedError() {
      return Object.assign(new Error('Model not allowed: __GATEWAY_ANTHROPIC_MODEL_OPUS__ (static)'), {
        code: 'MODEL_NOT_ALLOWED' as const,
        allowed: [{ provider: 'openai', modelId: '__GATEWAY_OPENAI_MODEL__' }],
        attempted: { provider: 'anthropic', modelId: '__GATEWAY_ANTHROPIC_MODEL_OPUS__' },
        offendingLabel: 'static',
      });
    }

    it('throws an HTTPException with status 422 when the error has code MODEL_NOT_ALLOWED', () => {
      const err = makeModelNotAllowedError();
      let caught: unknown;
      try {
        handleError(err, 'default');
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(HTTPException);
      expect((caught as HTTPException).status).toBe(422);
      expect((caught as HTTPException).cause).toBe(err);
    });

    it('writes a JSON body with code, message, allowed, attempted, offendingLabel', async () => {
      const err = makeModelNotAllowedError();
      let caught: HTTPException | undefined;
      try {
        handleError(err, 'default');
      } catch (e) {
        caught = e as HTTPException;
      }
      expect(caught).toBeDefined();
      const res = caught!.getResponse();
      expect(res.status).toBe(422);
      expect(res.headers.get('content-type')).toBe('application/json');
      const body = await res.json();
      expect(body).toEqual({
        error: {
          code: 'MODEL_NOT_ALLOWED',
          message: err.message,
          allowed: err.allowed,
          attempted: err.attempted,
          offendingLabel: err.offendingLabel,
        },
      });
    });

    it('falls through to default handling when code is not MODEL_NOT_ALLOWED', () => {
      const err = Object.assign(new Error('boom'), { status: 418 });
      let caught: HTTPException | undefined;
      try {
        handleError(err, 'default');
      } catch (e) {
        caught = e as HTTPException;
      }
      expect(caught).toBeInstanceOf(HTTPException);
      expect(caught!.status).toBe(418);
      expect(caught!.message).toBe('boom');
    });

    it('falls through to default handling when error is not an Error instance', () => {
      let caught: HTTPException | undefined;
      try {
        handleError({ code: 'MODEL_NOT_ALLOWED' } as unknown, 'default');
      } catch (e) {
        caught = e as HTTPException;
      }
      // Non-Error inputs must not be treated as model-not-allowed.
      expect(caught).toBeInstanceOf(HTTPException);
      expect(caught!.status).not.toBe(422);
    });
  });
});
