import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dilithium_crypto/dilithium_crypto.dart';

Uint8List randomSeed() {
  final random = Random.secure();
  return Uint8List.fromList(
      List<int>.generate(Dilithium.SEEDBYTES, (_) => random.nextInt(256)));
}

void main() {
  // generate key pair
  final DilithiumKeyPair keyPair = Dilithium.generateKeyPair(
      DilithiumParameterSpec.LEVEL3,
      randomSeed()); // Level2 or Level5 can be used as well

  // create signature
  final Uint8List validMsg = utf8.encode("Valid Message");
  final Uint8List signature = Dilithium.sign(keyPair.privateKey, validMsg);

  // verify signature with the public key and the message
  bool isValid = Dilithium.verify(keyPair.publicKey, signature, validMsg);
  assert(isValid);

  // verify signature with a modified message --> should be marked as invalid
  final modifiedMsg = utf8.encode("Modified Message");
  isValid = Dilithium.verify(keyPair.publicKey, signature, modifiedMsg);
  assert(!isValid);

  // obtain byte representation of the keys
  Uint8List publicKeyBytes = keyPair.publicKey.serialize();
  Uint8List privateKeyBytes = keyPair.privateKey.serialize();

  print("Private Key:");
  print(privateKeyBytes);
  print("\nPublic Key:");
  print(publicKeyBytes);

  // recreate keys from byte representation
  DilithiumPublicKey recreatedPublicKey = DilithiumPublicKey.deserialize(
      DilithiumParameterSpec.LEVEL3, publicKeyBytes);
  DilithiumPrivateKey recreatedPrivateKey = DilithiumPrivateKey.deserialize(
      DilithiumParameterSpec.LEVEL3, privateKeyBytes);

  // prove that the recreated keys are working
  final newMsg = utf8.encode("New Message");
  final Uint8List newSignature = Dilithium.sign(recreatedPrivateKey, newMsg);
  isValid = Dilithium.verify(recreatedPublicKey, newSignature, newMsg);
  assert(isValid);
}
