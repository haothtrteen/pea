'use strict';
/**
 * canary-js-licensing: license-signing module (WP4 measurement vehicle).
 *
 * HONEST DECLARATION — read before drawing any conclusion from this file:
 *
 * 1. This module is a measurement vehicle for the PEA protection pipeline,
 *    NOT a security authorization implementation. Client-side checks stay
 *    client-side checks after obfuscation; they never become authoritative.
 * 2. The signing key below is a PLANTED CANARY (`canary` markers, not a
 *    real credential). It exists so the pipeline can measure, before and
 *    after a protection transform, whether secret-shaped material remains
 *    visible in the production source.
 * 3. The baseline tests deliberately contain NO plaintext secret: the
 *    before/after exposure diff must isolate the production file, so a
 *    count change is attributable to the transform under measurement.
 * 4. Server-side enforcement belongs at a trust boundary; see the PEA
 *    report's remediation notes (logic_extraction) for the architecture
 *    recommendation this canary is designed to motivate.
 */
const crypto = require('node:crypto');

// CANARY: planted secret (harmless, not a real credential).
const SECRET_SIGNING_KEY = 'sk-canary-0000-0000-0000-000000';

function signLicense(payload) {
  return crypto.createHmac('sha256', SECRET_SIGNING_KEY).update(String(payload)).digest('hex');
}

function verifyLicense(payload, signature) {
  const expected = Buffer.from(signLicense(payload));
  const provided = Buffer.from(String(signature || ''));
  if (expected.length !== provided.length) {
    return false;
  }
  return crypto.timingSafeEqual(expected, provided);
}

module.exports = { signLicense, verifyLicense };
