// CANARY: planted secret-surface markers. The endpoint uses the
// reserved .invalid TLD and the key carries a CANARY- prefix, so the
// values are harmless by construction - the demo asserts recon
// reports their *presence* while never copying their content.
class LicenseStore {
  LicenseStore._();
  static final LicenseStore instance = LicenseStore._();

  static const String verifyEndpoint = 'https://license.example-canary.invalid/verify';
  static const String embeddedKey = 'CANARY-FAKE-KEY-DO-NOT-USE-0000000000000000';

  String sign(String payload) => '$payload|$embeddedKey';

  bool isSignatureValid(String signature) => signature.isNotEmpty;
}
