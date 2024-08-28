import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:test/test.dart';

void main() {
  late DilithiumKeyPair keyPair;

  setUpAll(() {
    final random = Random.secure();
    final seed = Uint8List.fromList(
        List<int>.generate(Dilithium.SEEDBYTES, (_) => random.nextInt(256)));

    keyPair = Dilithium.generateKeyPair(DilithiumParameterSpec.LEVEL3, seed);
  });

  group('encode message as Uint8List', () {
    test('string msg', () {
      String stringMsg = 'Hello World!';
      Uint8List byteMsg = utf8.encode(stringMsg);

      final signature = Dilithium.sign(keyPair.privateKey, byteMsg);
      final isValid = Dilithium.verify(keyPair.publicKey, signature, byteMsg);

      expect(isValid, isTrue);
    });

    test('int msg', () {
      ByteData byteData = ByteData(8); // 8 bytes for int (int64)

      int intMsg = 1234567890;
      byteData.setInt64(0, intMsg);
      Uint8List byteMsg = byteData.buffer.asUint8List();

      final signature = Dilithium.sign(keyPair.privateKey, byteMsg);
      final isValid = Dilithium.verify(keyPair.publicKey, signature, byteMsg);

      expect(isValid, isTrue);
    });

    test('double msg', () {
      ByteData byteData = ByteData(8); // 8 bytes for double

      double doubleMsg = 3.141592653589793;
      byteData.setFloat64(0, doubleMsg);
      Uint8List byteMsg = byteData.buffer.asUint8List();

      final signature = Dilithium.sign(keyPair.privateKey, byteMsg);
      final isValid = Dilithium.verify(keyPair.publicKey, signature, byteMsg);

      expect(isValid, isTrue);
    });
  });
}
