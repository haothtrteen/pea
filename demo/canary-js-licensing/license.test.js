'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { signLicense, verifyLicense } = require('./license.js');

// Baseline tests: verification infrastructure. Deliberately free of any
// plaintext secret - see license.js header (point 3).
test('signature round-trips', () => {
  const payload = 'device-0001|2026-12-31';
  assert.strictEqual(verifyLicense(payload, signLicense(payload)), true);
});

test('forged signature is rejected', () => {
  const payload = 'device-0001|2026-12-31';
  assert.strictEqual(verifyLicense(payload, '00'.repeat(32)), false);
});

test('tampered payload invalidates the signature', () => {
  const payload = 'device-0001|2026-12-31';
  const forged = signLicense(payload).slice(0, -2) + 'ff';
  assert.strictEqual(verifyLicense(payload, forged), false);
});
