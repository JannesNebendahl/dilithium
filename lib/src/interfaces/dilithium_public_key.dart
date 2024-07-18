import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

abstract class DilithiumPublicKey {
  String getAlgorithm();
  String getFormat();
  Uint8List getEncoded();
  DilithiumParameterSpec getSpec();
  Uint8List getRho();
  PolyVec getT1();
}