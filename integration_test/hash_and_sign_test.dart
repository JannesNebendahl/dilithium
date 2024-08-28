import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:test/test.dart';

main() {
  late DilithiumKeyPair keyPair;

  setUpAll(() {
    final random = Random.secure();
    final seed = Uint8List.fromList(
        List<int>.generate(Dilithium.SEEDBYTES, (_) => random.nextInt(256)));

    keyPair = Dilithium.generateKeyPair(DilithiumParameterSpec.LEVEL3, seed);
  });

  test('Hash and Sign Paradigma', () {
    String msg = "This is a long test message, longer than 32 bytes.";

    // Sender:
    Uint8List originalMsg = utf8.encode(msg);
    Uint8List hashValue = Uint8List.fromList(sha256.convert(originalMsg).bytes);

    final signature = Dilithium.sign(keyPair.privateKey, hashValue);

    // Receiver:
    String receivedMsg = msg;
    Uint8List receivedMsgBytes = utf8.encode(receivedMsg);
    Uint8List generatedHashValue =
        Uint8List.fromList(sha256.convert(receivedMsgBytes).bytes);

    bool isValid =
        Dilithium.verify(keyPair.publicKey, signature, generatedHashValue);
    expect(isValid, isTrue); // --> the received message is unmodified
  });
}
