import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/poly_vec.dart';

abstract class DilithiumPublicKey {
  String getAlgorithm();
  String getFormat();
  Uint8List getEncoded();
  DilithiumParameterSpec getSpec();
  Uint8List getRho();
  PolyVec getT1();
}