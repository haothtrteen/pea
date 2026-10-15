"""Rebuild the PEA demo canary project from scratch (idempotent).

The canary is a *static* Flutter-shaped source tree with deliberately planted
markers. It exists so the prototype-1.0 demo (and its tests) run against a
known, attributable project instead of anything real:

* planted authorization logic (``lib/auth/license_validator.dart``) so recon
  can demonstrate locating the asset under protection;
* a planted endpoint and a fake key using the ``.invalid`` TLD and a
  ``CANARY-`` prefix, so even an accidental leak of the scan output is
  harmless - this doubles as the secret-scan honeypot fixture (D3);
* no build artifacts: ``release``-level exposure is honestly ``unknown``
  until someone builds (real canary builds belong to the L2 verification
  layer, not to this demo).

Running this script rewrites the tree under ``demo/canary-flutter-licensing/``
byte-for-byte; the tests assert the checked-in tree matches, which is how
drift in the fixture gets caught.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANARY = ROOT / "demo" / "canary-flutter-licensing"

FILES: dict[str, str] = {
    "pubspec.yaml": (
        "name: flutter_licensing_app\n"
        "description: PEA demo canary - static source tree with planted markers\n"
        "publish_to: 'none'\n"
        "version: 1.0.0+1\n"
        "\n"
        "environment:\n"
        "  sdk: '>=3.0.0 <4.0.0'\n"
        "\n"
        "dependencies:\n"
        "  flutter:\n"
        "    sdk: flutter\n"
        "\n"
        "dev_dependencies:\n"
        "  flutter_test:\n"
        "    sdk: flutter\n"
        "\n"
        "flutter:\n"
        "  uses-material-design: true\n"
    ),
    "README.md": (
        "# canary: flutter-licensing\n"
        "\n"
        "PEA demo canary - a **static** Flutter-shaped source tree with planted\n"
        "markers. Not a buildable app; it exists for read-only recon and\n"
        "exposure-mapping demos.\n"
        "\n"
        "Planted markers (all intentional, all harmless):\n"
        "\n"
        "* `lib/auth/license_validator.dart` - authorization logic to locate\n"
        "* `lib/auth/license_store.dart` - planted endpoint (`*.invalid`) and\n"
        "  fake key (`CANARY-` prefix) for the secret-scan honeypot\n"
        "* `android/`, `ios/` - platform markers\n"
        "\n"
        "Rebuild with `python3 demo/build_canary.py`.\n"
    ),
    "lib/main.dart": (
        "import 'package:flutter/material.dart';\n"
        "\n"
        "import 'auth/license_validator.dart';\n"
        "\n"
        "void main() {\n"
        "  runApp(const FlutterLicensingApp());\n"
        "}\n"
        "\n"
        "class FlutterLicensingApp extends StatelessWidget {\n"
        "  const FlutterLicensingApp({super.key});\n"
        "\n"
        "  @override\n"
        "  Widget build(BuildContext context) {\n"
        "    return MaterialApp(\n"
        "      home: Scaffold(\n"
        "        body: Center(\n"
        "          child: Text('canary: ${LicenseValidator.instance.status}'),\n"
        "        ),\n"
        "      );\n"
        "  }\n"
        "}\n"
    ),
    "lib/auth/license_validator.dart": (
        "// CANARY: planted authorization logic - this file is the demo's\n"
        "// 'asset under protection'. The markers below (verifyLicense, RSA,\n"
        "// signature, token) are intentional so recon can locate them.\n"
        "class LicenseValidator {\n"
        "  LicenseValidator._();\n"
        "  static final LicenseValidator instance = LicenseValidator._();\n"
        "\n"
        "  String status = 'unchecked';\n"
        "\n"
        "  // verifyLicense: check the RSA signature over the license token.\n"
        "  bool verifyLicense(String token) {\n"
        "    final signature = LicenseStore.instance.sign(token);\n"
        "    status = LicenseStore.instance.isSignatureValid(signature) ? 'valid' : 'invalid';\n"
        "    return status == 'valid';\n"
        "  }\n"
        "}\n"
    ),
    "lib/auth/license_store.dart": (
        "// CANARY: planted secret-surface markers. The endpoint uses the\n"
        "// reserved .invalid TLD and the key carries a CANARY- prefix, so the\n"
        "// values are harmless by construction - the demo asserts recon\n"
        "// reports their *presence* while never copying their content.\n"
        "class LicenseStore {\n"
        "  LicenseStore._();\n"
        "  static final LicenseStore instance = LicenseStore._();\n"
        "\n"
        "  static const String verifyEndpoint = 'https://license.example-canary.invalid/verify';\n"
        "  static const String embeddedKey = 'CANARY-FAKE-KEY-DO-NOT-USE-0000000000000000';\n"
        "\n"
        "  String sign(String payload) => '$payload|$embeddedKey';\n"
        "\n"
        "  bool isSignatureValid(String signature) => signature.isNotEmpty;\n"
        "}\n"
    ),
    "android/build.gradle": (
        "buildscript {\n"
        "  ext.kotlin_version = '1.9.0'\n"
        "  repositories { google(); mavenCentral() }\n"
        "}\n"
        "\n"
        "allprojects {\n"
        "  repositories { google(); mavenCentral() }\n"
        "}\n"
    ),
    "android/app/build.gradle": (
        "plugins {\n"
        "  id 'com.android.application'\n"
        "  id 'org.jetbrains.kotlin.android'\n"
        "}\n"
        "\n"
        "android {\n"
        "  namespace 'com.example.flutter_licensing'\n"
        "  compileSdk 34\n"
        "  defaultConfig {\n"
        "    applicationId 'com.example.flutter_licensing'\n"
        "    minSdk 24\n"
        "    targetSdk 34\n"
        "    ndk {\n"
        "      // Declared ABIs: the L2 artifact layer emits one synthetic\n"
        "      // libapp.so per declared ABI, and build-integration asserts\n"
        "      // declared == shipped.\n"
        "      abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'\n"
        "    }\n"
        "  }\n"
        "  buildTypes {\n"
        "    release {\n"
        "      // NOTE: R8 here only touches the Java/Kotlin host layer.\n"
        "      // It does NOT touch the Dart AOT snapshot (libapp.so) - that\n"
        "      // distinction is the whole point of the demo scenario.\n"
        "      minifyEnabled true\n"
        "    }\n"
        "  }\n"
        "}\n"
    ),
    "android/app/src/main/AndroidManifest.xml": (
        "<manifest xmlns:android='http://schemas.android.com/apk/res/android'>\n"
        "  <application\n"
        "      android:label='flutter_licensing'\n"
        "      android:icon='@mipmap/ic_launcher'>\n"
        "    <activity android:name='.MainActivity' android:exported='true'>\n"
        "      <intent-filter>\n"
        "        <action android:name='android.intent.action.MAIN'/>\n"
        "        <category android:name='android.intent.category.LAUNCHER'/>\n"
        "      </intent-filter>\n"
        "    </activity>\n"
        "  </application>\n"
        "</manifest>\n"
    ),
    "android/app/src/main/kotlin/com/example/flutter_licensing/MainActivity.kt": (
        "package com.example.flutter_licensing\n"
        "\n"
        "import io.flutter.embedding.android.FlutterActivity\n"
        "\n"
        "class MainActivity : FlutterActivity()\n"
    ),
    "ios/Runner/Info.plist": (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<plist version='1.0'>\n"
        "<dict>\n"
        "  <key>CFBundleName</key>\n"
        "  <string>flutter_licensing</string>\n"
        "</dict>\n"
        "</plist>\n"
    ),
}


def build() -> int:
    CANARY.mkdir(parents=True, exist_ok=True)
    for rel, content in FILES.items():
        path = CANARY / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"canary rebuilt at {CANARY} ({len(FILES)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(build())
