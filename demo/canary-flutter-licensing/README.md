# canary: flutter-licensing

PEA demo canary - a **static** Flutter-shaped source tree with planted
markers. Not a buildable app; it exists for read-only recon and
exposure-mapping demos.

Planted markers (all intentional, all harmless):

* `lib/auth/license_validator.dart` - authorization logic to locate
* `lib/auth/license_store.dart` - planted endpoint (`*.invalid`) and
  fake key (`CANARY-` prefix) for the secret-scan honeypot
* `android/`, `ios/` - platform markers

Rebuild with `python3 demo/build_canary.py`.
