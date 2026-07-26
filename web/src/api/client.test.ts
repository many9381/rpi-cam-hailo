import { describe, expect, it, vi } from 'vitest';

import { ApiClient, ApiError, UnauthorizedError } from './client';
import { parseLoginResult, parsePrincipal, parseReauthenticateResult } from './contracts';

const jsonResponse = (value: unknown, status = 200) => new Response(
  JSON.stringify(value),
  { status, headers: { 'Content-Type': 'application/json' } },
);

describe('ApiClient', () => {
  it('invokes the fetch implementation without changing its receiver', async () => {
    let receiver: unknown = null;
    const fetchMock = vi.fn(function (this: unknown) {
      receiver = this;
      return Promise.resolve(jsonResponse({
        username: 'operator.one',
        role: 'viewer',
      }));
    });
    const client = new ApiClient(fetchMock);

    await expect(client.getJson('/api/v1/auth/me', parsePrincipal))
      .resolves.toEqual({ username: 'operator.one', role: 'viewer' });
    expect(receiver).toBeUndefined();
  });

  it('sends management JSON with same-origin credentials and parses the result', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      role: 'administrator',
      idle_expires_at_seconds: 100,
    }));
    const unauthorized = vi.fn();
    const client = new ApiClient(fetchMock, unauthorized);

    await expect(client.postJson('/api/v1/auth/login', {
      username: 'operator.one',
      password: 'NorthStar!9',
    }, parseLoginResult)).resolves.toEqual({
      role: 'administrator',
      idle_expires_at_seconds: 100,
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/login', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Camera-Request': 'management',
      },
      body: JSON.stringify({
        username: 'operator.one',
        password: 'NorthStar!9',
      }),
    }));
  });

  it('sends PUT management JSON with same-origin credentials and the supplied signal', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      username: 'operator.one',
      role: 'administrator',
    }));
    const signal = new AbortController().signal;
    const client = new ApiClient(fetchMock);

    await expect(client.putJson(
      '/api/v1/settings/runtime',
      { expected_revision: 4, settings: {} },
      parsePrincipal,
      signal,
    )).resolves.toEqual({ username: 'operator.one', role: 'administrator' });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/settings/runtime', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Camera-Request': 'management',
      },
      body: JSON.stringify({ expected_revision: 4, settings: {} }),
      signal,
    });
  });

  it('deletes JSON with the management header, supplied signal, and parser', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ deleted: true }));
    const parser = vi.fn((value: unknown) => {
      if (typeof value !== 'object' || value === null ||
          (value as { deleted?: unknown }).deleted !== true) {
        throw new Error('Invalid delete response');
      }
      return { deleted: true as const };
    });
    const signal = new AbortController().signal;
    const client = new ApiClient(fetchMock);

    await expect(client.deleteJson('/api/v1/security/users/7', parser, signal))
      .resolves.toEqual({ deleted: true });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/security/users/7', {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { 'X-Camera-Request': 'management' },
      signal,
    });
    expect(parser).toHaveBeenCalledWith({ deleted: true });
  });

  it('notifies the global handler for a DELETE 401 only', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ code: 'E_SESSION_EXPIRED' }, 401))
      .mockResolvedValueOnce(jsonResponse({
        code: 'E_ACCESS_DENIED',
        message: 'rejected viewer-secret',
        echoed_body: { password: 'viewer-secret' },
      }, 403));
    const unauthorized = vi.fn();
    const client = new ApiClient(fetchMock, unauthorized);
    const parser = (value: unknown) => value;

    await expect(client.deleteJson('/api/v1/security/users/7', parser))
      .rejects.toEqual(new UnauthorizedError('E_SESSION_EXPIRED'));
    expect(unauthorized).toHaveBeenCalledTimes(1);

    const error = await client.deleteJson('/api/v1/security/users/7', parser)
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({
      status: 403,
      code: 'E_ACCESS_DENIED',
      message: 'Request failed',
    });
    expect(String(error)).not.toContain('viewer-secret');
    expect(unauthorized).toHaveBeenCalledTimes(1);
  });

  it('gets JSON with same-origin credentials and the supplied signal', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      username: 'operator.one',
      role: 'viewer',
    }));
    const signal = new AbortController().signal;
    const client = new ApiClient(fetchMock);

    await expect(client.getJson('/api/v1/auth/me', parsePrincipal, signal))
      .resolves.toEqual({ username: 'operator.one', role: 'viewer' });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/me', {
      credentials: 'same-origin',
      signal,
    });
  });

  it('returns blobs requested with same-origin credentials', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      new TextEncoder().encode('jpeg'),
      { headers: { 'Content-Type': 'image/jpeg' } },
    ));
    const signal = new AbortController().signal;
    const client = new ApiClient(fetchMock);

    const actual = await client.getBlob('/api/v1/cameras/main/snapshot.jpg', signal);

    expect(actual.type).toBe('image/jpeg');
    await expect(actual.text()).resolves.toBe('jpeg');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cameras/main/snapshot.jpg', {
      credentials: 'same-origin',
      signal,
    });
  });

  it('reduces server JSON errors without retaining the submitted body', async () => {
    const secret = 'NorthStar!9';
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      code: 'E_ACCESS_DENIED',
      message: `rejected ${secret}`,
      echoed_body: { password: secret },
    }, 403));
    const client = new ApiClient(fetchMock);

    const error = await client.postJson('/api/v1/auth/login', {
      username: 'operator.one',
      password: secret,
    }, parseLoginResult).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 403,
      code: 'E_ACCESS_DENIED',
      message: 'Request failed',
    });
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(String(error)).not.toContain(secret);
    expect(error).not.toHaveProperty('body');
    expect(error).not.toHaveProperty('response');
  });

  it('uses a generic code when the error response is not valid JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('upstream detail', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' },
    }));
    const client = new ApiClient(fetchMock);

    await expect(client.getBlob('/api/v1/cameras/main/snapshot.jpg')).rejects.toMatchObject({
      status: 503,
      code: 'E_REQUEST_FAILED',
      message: 'Request failed',
    });
  });

  it('notifies the current unauthorized handler exactly once per 401 response', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ code: 'E_SESSION_EXPIRED' }, 401))
      .mockResolvedValueOnce(jsonResponse({ code: 'E_AUTHENTICATION_REQUIRED' }, 401));
    const initialHandler = vi.fn();
    const currentHandler = vi.fn();
    const client = new ApiClient(fetchMock, initialHandler);
    client.setUnauthorizedHandler(currentHandler);

    await expect(client.getJson('/api/v1/auth/me', parsePrincipal))
      .rejects.toEqual(new UnauthorizedError('E_SESSION_EXPIRED'));
    expect(initialHandler).not.toHaveBeenCalled();
    expect(currentHandler).toHaveBeenCalledTimes(1);

    client.setUnauthorizedHandler(null);
    await expect(client.getBlob('/api/v1/cameras/main/snapshot.jpg'))
      .rejects.toEqual(new UnauthorizedError());
    expect(currentHandler).toHaveBeenCalledTimes(1);
  });

  it('throws without invoking the unauthorized handler when management authority lapses', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ code: 'E_MANAGEMENT_REAUTHENTICATION_REQUIRED' }, 401),
    );
    const handler = vi.fn();
    const client = new ApiClient(fetchMock, handler);

    await expect(client.getJson('/api/v1/auth/me', parsePrincipal))
      .rejects.toEqual(new UnauthorizedError('E_MANAGEMENT_REAUTHENTICATION_REQUIRED'));
    expect(handler).not.toHaveBeenCalled();
  });

  it('throws without invoking the unauthorized handler when a reauthentication password is rejected', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ code: 'E_AUTHENTICATION_FAILED' }, 401),
    );
    const handler = vi.fn();
    const client = new ApiClient(fetchMock, handler);

    await expect(client.postJson(
      '/api/v1/auth/reauthenticate',
      { password: 'WrongPass9!' },
      parseReauthenticateResult,
    )).rejects.toEqual(new UnauthorizedError('E_AUTHENTICATION_FAILED'));
    expect(handler).not.toHaveBeenCalled();
  });

  it('still invokes the unauthorized handler when authentication is genuinely required', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ code: 'E_AUTHENTICATION_REQUIRED' }, 401),
    );
    const handler = vi.fn();
    const client = new ApiClient(fetchMock, handler);

    await expect(client.getJson('/api/v1/auth/me', parsePrincipal))
      .rejects.toEqual(new UnauthorizedError('E_AUTHENTICATION_REQUIRED'));
    expect(handler).toHaveBeenCalledTimes(1);
  });
});
