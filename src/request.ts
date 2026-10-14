import { parseRefusal, sanitizeKinds, VoidmailRefusal } from './refusal.js';

class VoidmailRateLimitError extends Error {}

export interface ResponseMeta { contentWarning?: string[]; status?: number }

export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

/** Read at most `max` bytes of an error body; anything larger is not a refusal. */
async function boundedErrorJson(response: Response, max = 16 * 1024): Promise<unknown> {
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch { return null; } finally { reader.releaseLock(); }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch { return null; }
}

/** One bounded attempt. Never retry a send or replay credentials on redirects. */
export async function requestJson(fetcher: typeof fetch, url: string, init: RequestInit, timeoutMs = 20_000, meta?: ResponseMeta, maxBytes = DEFAULT_MAX_BYTES): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const uncertain = init.method !== 'GET';
  let status: number | undefined;
  try {
    const response = await fetcher(url, { ...init, redirect: 'error', signal: controller.signal });
    status = response.status;
    if (meta) meta.status = response.status;
    if (response.status === 429) {
      // The pending-request cap and the owner-auth failure limit share 429 with rate limits; only their closed words are recognised.
      const capped = parseRefusal(await boundedErrorJson(response), 429);
      if (capped?.code === 'too_many_pending_requests' || capped?.code === 'owner_auth_rate_limited') throw new VoidmailRefusal(capped);
      const raw = response.headers.get('Retry-After');
      const seconds = raw && /^\d{1,8}$/.test(raw) ? Math.max(1, Number(raw)) : null;
      await response.body?.cancel().catch(() => {});
      throw new VoidmailRateLimitError(`Voidmail request was rate limited (HTTP 429).${seconds ? ` Wait at least ${seconds} seconds before another attempt.` : ' Check sending limits before another attempt.'} No automatic retry. If an earlier send was uncertain, reconcile it before sending again.`);
    }
    if (!response.ok) {
      // Only closed policy words are recognised; every other byte of the body is dropped.
      const refusal = [400, 401, 403, 404, 409, 422, 503].includes(response.status) ? parseRefusal(await boundedErrorJson(response), response.status) : null;
      if (refusal) throw new VoidmailRefusal(refusal);
      await response.body?.cancel().catch(() => {});
      throw new Error(`Voidmail API returned HTTP ${response.status}.`);
    }
    if (meta) {
      const kinds = sanitizeKinds(response.headers.get('X-Voidmail-Content-Warning') ?? '');
      if (kinds.length) meta.contentWarning = kinds;
    }
    if (!response.body) throw new Error('Missing response body.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let size = 0, text = '';
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) {
          await reader.cancel();
          throw new Error(`Response exceeds the ${Math.round(maxBytes / 1048576)} MiB limit; request fewer messages.`);
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } finally { reader.releaseLock(); }
    const data: unknown = JSON.parse(text);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid API response.');
    return data;
  } catch (error) {
    if (error instanceof VoidmailRateLimitError || error instanceof VoidmailRefusal) throw error;
    // Never reflect provider error bodies, transport errors, or credentials.
    const context = status === undefined ? '' : ` HTTP ${status}.`;
    throw new Error((uncertain
      ? 'Voidmail operation was not confirmed. Its outcome may be unknown; do not automatically retry or resend. Reconcile the original request.'
      : `Voidmail read failed or exceeded its ${Math.round(timeoutMs / 1000)}-second / ${Math.round(maxBytes / 1048576)} MiB bound. Request fewer messages or try the read again.`) + context);
  } finally { clearTimeout(timer); }
}

/**
 * One bounded GET of a binary body (sealed ciphertext). Same rules as requestJson: no
 * redirects, no retry, a hard size bound, and no server text reflected in errors.
 */
export async function requestBytes(fetcher: typeof fetch, url: string, init: RequestInit, timeoutMs = 20_000, maxBytes = DEFAULT_MAX_BYTES): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let status: number | undefined;
  try {
    const response = await fetcher(url, { ...init, method: 'GET', redirect: 'error', signal: controller.signal });
    status = response.status;
    if (!response.ok) {
      const refusal = [401, 404, 409, 503].includes(response.status) ? parseRefusal(await boundedErrorJson(response), response.status) : null;
      if (refusal) throw new VoidmailRefusal(refusal);
      await response.body?.cancel().catch(() => {});
      throw new Error(`Voidmail API returned HTTP ${response.status}.`);
    }
    if (!response.body) throw new Error('Missing response body.');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) { await reader.cancel(); throw new Error('too large'); }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const out = new Uint8Array(size); let offset = 0;
    for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
    return out;
  } catch (error) {
    if (error instanceof VoidmailRefusal) throw error;
    throw new Error(`Voidmail read failed or exceeded its ${Math.round(timeoutMs / 1000)}-second / ${Math.round(maxBytes / 1048576)} MiB bound.${status === undefined ? '' : ` HTTP ${status}.`}`);
  } finally { clearTimeout(timer); }
}
