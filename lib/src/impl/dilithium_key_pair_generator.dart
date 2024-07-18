import 'dart:math';
import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';

class DilithiumKeyPairGenerator {
  final DilithiumParameterSpec _params;
  final SecureRandom _random;

  DilithiumKeyPairGenerator(this._params) : _random = _getSecureRandom();

  DilithiumKeyPair generateKeyPair() {

    Uint8List seed = Uint8List(0);
    try {
      seed = _random.nextBytes(32);
      return Dilithium.generateKeyPair(_params, seed);
    } finally {
      Utils.clear(seed);
    }
  }

  static SecureRandom _getSecureRandom() {
    final secureRandom = FortunaRandom();

    // Seed the generator with some entropy
    final seedSource = Random.secure();
    final seeds = <int>[];
    for (int i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(256));
    }

    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }
}