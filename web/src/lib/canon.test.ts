import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalize, canonicalizeJSON, digest, digestJSON } from './canon.ts';

interface CanonicalVector {
  name: string;
  input_raw: string;
  expected_bytes: string;
  expected_hex_hash: string;
  should_fail: boolean;
  failure_reason?: string;
}

interface VectorsFile {
  description: string;
  vectors: CanonicalVector[];
}

test('RFC 8785 TypeScript canonicalization & golden vectors', async (t) => {
  const vectorsPath = resolve(process.cwd(), 'testdata', 'canon', 'vectors.json');
  const fileContent = readFileSync(vectorsPath, 'utf-8');
  const vf: VectorsFile = JSON.parse(fileContent);

  for (const vec of vf.vectors) {
    await t.test(vec.name, async () => {
      if (vec.should_fail) {
        assert.throws(
          () => canonicalizeJSON(vec.input_raw),
          /RFC 8785|JSON|SyntaxError/,
          `Expected ${vec.name} to fail validation`
        );
        return;
      }

      const canonicalResult = canonicalizeJSON(vec.input_raw);
      assert.equal(
        canonicalResult,
        vec.expected_bytes,
        `Canonical bytes mismatch for vector: ${vec.name}`
      );

      const hexHash = await digestJSON(vec.input_raw);
      assert.equal(
        hexHash,
        vec.expected_hex_hash,
        `SHA-256 hash mismatch for vector: ${vec.name}`
      );
    });
  }
});

test('Direct value canonicalization and number edge cases', async () => {
  assert.equal(canonicalize(null), 'null');
  assert.equal(canonicalize(true), 'true');
  assert.equal(canonicalize(false), 'false');
  assert.equal(canonicalize(-0), '0');
  assert.equal(canonicalize(0), '0');

  // Object key sorting
  assert.equal(canonicalize({ b: 2, a: 1 }), '{"a":1,"b":2}');

  // Non-finite numbers must throw
  assert.throws(() => canonicalize(NaN));
  assert.throws(() => canonicalize(Infinity));
  assert.throws(() => canonicalize(-Infinity));

  // Undefined in object omitted
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}');
});
