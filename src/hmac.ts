// HMAC signing / verification for the Agent Games platform.
// The signature is computed over the RAW request/response body (not the
// parsed JSON) and compared with the x-agent-games-signature header.
// Uses a timing-safe comparison so a wrong signature leaks nothing.
import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Compute the HMAC-SHA256 hex digest of a raw body. */
export function signBody(secret: string, rawBody: Buffer | string): string {
  const h = createHmac("sha256", secret);
  h.update(rawBody);
  return h.digest("hex");
}

/**
 * Verify an inbound signature. Returns true only if the header is present
 * and matches the HMAC of the raw body (timing-safe). Accepts the digest
 * with or without a "sha256=" prefix.
 */
export function verifySignature(
  secret: string,
  rawBody: Buffer | string,
  headerValue: string | string[] | undefined,
): boolean {
  if (typeof headerValue !== "string" || headerValue.length === 0) return false;
  const provided = headerValue.startsWith("sha256=")
    ? headerValue.slice("sha256=".length)
    : headerValue;
  const expected = signBody(secret, rawBody);
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
