import 'dart:typed_data';
import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/packing_utils.dart';
import 'package:dilithium/src/poly_vec.dart';

class DilithiumPrivateKey {
  final DilithiumParameterSpec _spec;
  final Uint8List _rho;
  final Uint8List _tr;
  final Uint8List _K;
  final PolyVec _s1;
  final PolyVec _s2;
  final PolyVec _t0;
  final PolyVec _s1Hat;
  final PolyVec _s2Hat;
  final PolyVec _t0Hat;
  final Uint8List _prvbytes;
  final List<PolyVec> _A;

  DilithiumPrivateKey(
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
    this._t0Hat
  );

  static DilithiumPrivateKey deserialize(DilithiumParameterSpec spec, Uint8List encodedData){
    return PackingUtils.unpackPrivateKey(spec, encodedData);
  }

  Uint8List serialize() {
    return _prvbytes;
  }

  DilithiumParameterSpec get spec => _spec;
  Uint8List get rho => _rho;
  Uint8List get tr => _tr;
  Uint8List get K => _K;
  PolyVec get s1 => _s1;
  PolyVec get s2 => _s2;
  PolyVec get t0 => _t0;
  PolyVec get s1Hat => _s1Hat;
  PolyVec get s2Hat => _s2Hat;
  PolyVec get t0Hat => _t0Hat;
  List<PolyVec> get A => _A;

}
