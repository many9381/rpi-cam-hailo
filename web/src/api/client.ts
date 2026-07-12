import type { CameraApiClient, Parser } from './types';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message = 'Request failed',
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export class UnauthorizedError extends ApiError {
  constructor(code = 'E_AUTHENTICATION_REQUIRED') {
    super(401, code, 'Authentication required');
    this.name = 'UnauthorizedError';
  }
}

type Fetch = typeof fetch;

export class ApiClient implements CameraApiClient {
  private unauthorizedHandler: (() => void) | null;

  constructor(
    private readonly fetchImpl: Fetch = fetch,
    unauthorizedHandler: (() => void) | null = null,
  ) {
    this.unauthorizedHandler = unauthorizedHandler;
  }

  setUnauthorizedHandler(handler: (() => void) | null): void {
    this.unauthorizedHandler = handler;
  }

  async getJson<T>(
    path: string,
    parser: Parser<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    const fetchImpl = this.fetchImpl;
    const response = await fetchImpl(path, {
      credentials: 'same-origin',
      signal,
    });
    await this.requireSuccess(response);
    return parser(await response.json());
  }

  async postJson<B, T>(
    path: string,
    body: B,
    parser: Parser<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    const fetchImpl = this.fetchImpl;
    const response = await fetchImpl(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Camera-Request': 'management',
      },
      body: JSON.stringify(body),
      signal,
    });
    await this.requireSuccess(response);
    return parser(await response.json());
  }

  async getBlob(path: string, signal?: AbortSignal): Promise<Blob> {
    const fetchImpl = this.fetchImpl;
    const response = await fetchImpl(path, {
      credentials: 'same-origin',
      signal,
    });
    await this.requireSuccess(response);
    return response.blob();
  }

  private async requireSuccess(response: Response): Promise<void> {
    if (response.ok) {
      return;
    }

    const code = await this.readErrorCode(response);
    if (response.status === 401) {
      this.unauthorizedHandler?.();
      throw new UnauthorizedError(code ?? undefined);
    }
    throw new ApiError(response.status, code ?? 'E_REQUEST_FAILED');
  }

  private async readErrorCode(response: Response): Promise<string | null> {
    try {
      const value: unknown = await response.json();
      if (typeof value === 'object' && value !== null &&
          'code' in value && typeof value.code === 'string' && value.code.length > 0) {
        return value.code;
      }
    } catch {
      // Error response details are deliberately discarded.
    }
    return null;
  }
}
