/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 Digester.
 * Compatible with Node.js and Browser environments.
 */

// Helper to check if a value is a plain object
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Escapes a string according to RFC 8785 §3.2.2.2.
 */
function escapeString(str: string): string {
  let result = '"';
  for (let i = 0; i < str.length; i++) {
    const ch = str.charAt(i);
    const code = str.charCodeAt(i);

    switch (ch) {
      case '"':
        result += '\\"';
        break;
      case '\\':
        result += '\\\\';
        break;
      case '\b':
        result += '\\b';
        break;
      case '\f':
        result += '\\f';
        break;
      case '\n':
        result += '\\n';
        break;
      case '\r':
        result += '\\r';
        break;
      case '\t':
        result += '\\t';
        break;
      default:
        if (code < 0x20) {
          result += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          result += ch;
        }
        break;
    }
  }
  result += '"';
  return result;
}

/**
 * Serializes a number according to RFC 8785 §3.2.2.3.
 */
function serializeNumber(num: number): string {
  if (!Number.isFinite(num)) {
    throw new Error(`RFC 8785: non-finite number not allowed: ${num}`);
  }
  // RFC 8785: -0 must be serialized as 0
  if (Object.is(num, -0)) {
    return '0';
  }
  return String(num);
}

/**
 * Canonicalizes a JavaScript value to RFC 8785 canonical JSON string.
 */
export function canonicalize(v: unknown): string {
  if (v === null) {
    return 'null';
  }
  if (v === undefined) {
    throw new Error('RFC 8785: undefined is not a valid JSON value');
  }

  const t = typeof v;
  if (t === 'boolean') {
    return v ? 'true' : 'false';
  }
  if (t === 'number') {
    return serializeNumber(v as number);
  }
  if (t === 'string') {
    return escapeString(v as string);
  }

  if (Array.isArray(v)) {
    const items = v.map((item) => (item === undefined ? 'null' : canonicalize(item)));
    return '[' + items.join(',') + ']';
  }

  if (isPlainObject(v)) {
    // Keys MUST be sorted in ascending order by UTF-16 code units (RFC 8785 §3.2.3)
    const keys = Object.keys(v).sort((a, b) => {
      if (a === b) return 0;
      return a < b ? -1 : 1;
    });

    const entries: string[] = [];
    for (const key of keys) {
      const val = v[key];
      // Omit undefined values from objects as per JSON specification
      if (val === undefined) {
        continue;
      }
      entries.push(escapeString(key) + ':' + canonicalize(val));
    }
    return '{' + entries.join(',') + '}';
  }

  throw new Error(`RFC 8785: unsupported type: ${t}`);
}

/**
 * Validates and canonicalizes a raw JSON string.
 */
export function canonicalizeJSON(raw: string): string {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error('RFC 8785: cannot canonicalize empty JSON string');
  }
  // Parse will throw on malformed JSON
  const parsed = JSON.parse(raw);
  return canonicalize(parsed);
}

/**
 * Computes the SHA-256 hex digest of canonicalized JSON.
 */
export async function digest(v: unknown): Promise<string> {
  const canonicalStr = canonicalize(v);
  return digestString(canonicalStr);
}

/**
 * Computes the SHA-256 hex digest of a raw JSON string after canonicalization.
 */
export async function digestJSON(raw: string): Promise<string> {
  const canonicalStr = canonicalizeJSON(raw);
  return digestString(canonicalStr);
}

/**
 * SHA-256 hash calculation supporting both Node.js crypto and Web Crypto API.
 */
async function digestString(str: string): Promise<string> {
  const utf8Bytes = new TextEncoder().encode(str);

  // Check Web Crypto API (Browser or Node 16+)
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', utf8Bytes);
    const hashArray = Array.from(new Uint8Array(hashBuf));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Fallback to Node.js crypto module if available
  const nodeCrypto = await import('node:crypto');
  return nodeCrypto.createHash('sha256').update(utf8Bytes).digest('hex');
}
