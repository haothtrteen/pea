import 'package:flutter/material.dart';

import 'auth/license_validator.dart';

void main() {
  runApp(const FlutterLicensingApp());
}

class FlutterLicensingApp extends StatelessWidget {
  const FlutterLicensingApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: Center(
          child: Text('canary: ${LicenseValidator.instance.status}'),
        ),
      );
  }
}
