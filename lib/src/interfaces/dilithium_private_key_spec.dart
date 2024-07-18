import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

class DilithiumPrivateKeySpec extends DilithiumKeySpec {
  DilithiumPrivateKeySpec(super.paramSpec, Uint8List super.data);
}