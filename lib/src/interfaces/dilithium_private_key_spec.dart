import 'dart:typed_data';

import 'package:dilithium/src/interfaces/dilithium_key_spec.dart';

class DilithiumPrivateKeySpec extends DilithiumKeySpec {
  DilithiumPrivateKeySpec(super.paramSpec, Uint8List super.data);
}