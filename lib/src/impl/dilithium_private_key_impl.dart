import 'dart:typed_data';
import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/poly_vec.dart';

class DilithiumPrivateKeyImpl implements DilithiumPrivateKey {
  final Uint8List _rho;
  final Uint8List _tr;
  final Uint8List _K;
  final PolyVec _s1;
  final PolyVec _s2;
  final PolyVec _t0;
  final PolyVec _s1Hat;
  final PolyVec _s2Hat;
  final PolyVec _t0Hat;
  final DilithiumParameterSpec _spec;
  final Uint8List _prvbytes;
  final List<PolyVec> _A;

  DilithiumPrivateKeyImpl(
      this._spec,
      this._rho,
      this._K,
      this._tr,
      this._s1,
      this._s2,
      this._t0,
      this._prvbytes,
      this._A,
      this._s1Hat,
      this._s2Hat,
      this._t0Hat);

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
    return _prvbytes;
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
  Uint8List getTr() {
    return _tr;
  }

  @override
  Uint8List getK() {
    return _K;
  }

  @override
  PolyVec getS1() {
    return _s1;
  }

  @override
  PolyVec getS2() {
    return _s2;
  }

  @override
  PolyVec getT0() {
    return _t0;
  }

  List<PolyVec> getA() {
    return _A;
  }

  @override
  PolyVec getS1Hat() {
    return _s1Hat;
  }

  @override
  PolyVec getS2Hat() {
    return _s2Hat;
  }

  @override
  PolyVec getT0Hat() {
    return _t0Hat;
  }
}
