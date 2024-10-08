import 'dart:typed_data';

import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:dilithium_crypto/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('Utils', () {
    test('concat', () {
      Uint8List a = Uint8List.fromList([1, 2, 3]);
      Uint8List b = Uint8List.fromList([4, 5, 6]);
      Uint8List expected = Uint8List.fromList([1, 2, 3, 4, 5, 6]);

      final actual = Utils.concat([a, b]);

      expect(actual, expected);
    });

    test('getSHAKE256Digest', () {
      final data = Uint8List.fromList('test'.codeUnits);
      final expected = Uint8List.fromList([
        0xB5,
        0x4F,
        0xF7,
        0x25,
        0x57,
        0x5,
        0xA7,
        0x1E,
        0xE2,
        0x92,
        0x5E,
        0x4A,
        0x3E,
        0x30,
        0xE4,
        0x1A,
        0xED,
        0x48,
        0x9A,
        0x57,
        0x9D,
        0x55,
        0x95,
        0xE0,
        0xDF,
        0x13,
        0xE3,
        0x2E,
        0x1E,
        0x4D,
        0xD2,
        0x2
      ]);

      final actual = Utils.getSHAKE256Digest(32, [data]);

      expect(actual, expected);
    });

    test('crh', () {
      final data = Uint8List.fromList('test'.codeUnits);
      final expected = Uint8List.fromList([
        0xB5,
        0x4F,
        0xF7,
        0x25,
        0x57,
        0x5,
        0xA7,
        0x1E,
        0xE2,
        0x92,
        0x5E,
        0x4A,
        0x3E,
        0x30,
        0xE4,
        0x1A,
        0xED,
        0x48,
        0x9A,
        0x57,
        0x9D,
        0x55,
        0x95,
        0xE0,
        0xDF,
        0x13,
        0xE3,
        0x2E,
        0x1E,
        0x4D,
        0xD2,
        0x2
      ]);

      final actual = Utils.crh(data);

      expect(actual, expected);
    });

    test('mucrh', () {
      final data = Uint8List.fromList('test'.codeUnits);
      final expected = Uint8List.fromList([
        0xB5,
        0x4F,
        0xF7,
        0x25,
        0x57,
        0x5,
        0xA7,
        0x1E,
        0xE2,
        0x92,
        0x5E,
        0x4A,
        0x3E,
        0x30,
        0xE4,
        0x1A,
        0xED,
        0x48,
        0x9A,
        0x57,
        0x9D,
        0x55,
        0x95,
        0xE0,
        0xDF,
        0x13,
        0xE3,
        0x2E,
        0x1E,
        0x4D,
        0xD2,
        0x2,
        0xA7,
        0xC7,
        0xF6,
        0x8B,
        0x31,
        0xD6,
        0x41,
        0x8D,
        0x98,
        0x45,
        0xEB,
        0x4D,
        0x75,
        0x7A,
        0xDD,
        0xA6,
        0xAB,
        0x18,
        0x9E,
        0x1B,
        0xB3,
        0x40,
        0xDB,
        0x81,
        0x8E,
        0x5B,
        0x3B,
        0xC7,
        0x25,
        0xD9,
        0x92,
        0xFA
      ]);

      final actual = Utils.mucrh(data);

      expect(actual, expected);
    });

    test('getSigLength', () {
      expect(Utils.getSigLength(DilithiumParameterSpec.LEVEL2), 2420);

      expect(Utils.getSigLength(DilithiumParameterSpec.LEVEL3), 3293);

      expect(Utils.getSigLength(DilithiumParameterSpec.LEVEL5), 4595);
    });
  });
}
