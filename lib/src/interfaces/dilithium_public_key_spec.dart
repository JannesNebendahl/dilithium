
import 'dart:typed_data';

import 'package:dilithium/src/interfaces/dilithium_key_spec.dart';

class DilithiumPublicKeySpec extends DilithiumKeySpec {
  DilithiumPublicKeySpec(super.paramSpec, Uint8List super.data);
}