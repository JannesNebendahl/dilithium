// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';

import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:dilithium_crypto/src/packing_utils.dart';
import 'package:dilithium_crypto/src/poly_vec.dart';

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
