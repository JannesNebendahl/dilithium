

import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/packing_utils.dart';
import 'package:dilithium/src/impl/poly_vec.dart';

class DilithiumPublicKey {
  final DilithiumParameterSpec _spec;
  final Uint8List _rho;
  final PolyVec _t1;
  final List<PolyVec> _A;
  final Uint8List _pubbytes;

  DilithiumPublicKey(
    this._spec,
    this._rho,
    this._t1,
    this._pubbytes,
    this._A
  );

  static DilithiumPublicKey deserialize(DilithiumParameterSpec spec, Uint8List encodedData){
    return PackingUtils.unpackPublicKey(spec, encodedData);
  }

  Uint8List serialize() {
    return _pubbytes;
  }

  DilithiumParameterSpec get spec => _spec;
  Uint8List get rho => _rho;
  PolyVec get t1 => _t1;
  List<PolyVec> get A => _A;
}
