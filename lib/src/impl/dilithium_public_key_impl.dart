

import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/poly_vec.dart';

class DilithiumPublicKeyImpl implements DilithiumPublicKey {
  final Uint8List _rho;
  final PolyVec _t1;
  final List<PolyVec> _A;
  final DilithiumParameterSpec _spec;
  final Uint8List _pubbytes;

  DilithiumPublicKeyImpl(
      this._spec,
      this._rho,
      this._t1,
      this._pubbytes,
      this._A);

  @override
  String getAlgorithm() {
    return "Dilithium";
  }

  @override
  String getFormat() {
    return "RAW";
  }

  @override
  Uint8List getEncoded() {
    return _pubbytes;
  }

  @override
  DilithiumParameterSpec getSpec() {
    return _spec;
  }

  @override
  Uint8List getRho() {
    return _rho;
  }

  @override
  PolyVec getT1() {
    return _t1;
  }

  List<PolyVec> getA() {
    return _A;
  }
}
