import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

abstract class DilithiumPrivateKey {
  String getAlgorithm();
  String getFormat();
  Uint8List getEncoded();
  DilithiumParameterSpec getSpec();
  Uint8List getRho();
  Uint8List getTr();
  Uint8List getK();
  PolyVec getS1();
  PolyVec getS2();
  PolyVec getT0();
  PolyVec getS1Hat();
  PolyVec getS2Hat();
  PolyVec getT0Hat();
}