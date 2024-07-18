import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

class DilithiumKeySpec {
  final Uint8List _bytes;
  final DilithiumParameterSpec _paramSpec;

  DilithiumKeySpec(this._paramSpec, this._bytes);

  List<int> getBytes() {
    return _bytes;
  }

  DilithiumParameterSpec getParameterSpec() {
    return _paramSpec;
  }
}