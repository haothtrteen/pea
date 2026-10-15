// CANARY: planted authorization logic - this file is the demo's
// 'asset under protection'. The markers below (verifyLicense, RSA,
// signature, token) are intentional so recon can locate them.
class LicenseValidator {
  LicenseValidator._();
  static final LicenseValidator instance = LicenseValidator._();

  String status = 'unchecked';

  // verifyLicense: check the RSA signature over the license token.
  bool verifyLicense(String token) {
    final signature = LicenseStore.instance.sign(token);
    status = LicenseStore.instance.isSignatureValid(signature) ? 'valid' : 'invalid';
    return status == 'valid';
  }
}
