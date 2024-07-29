import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

Uint8List randomSeed(){
  final random = Random.secure();
  return Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
}

void main() {
  
  final DilithiumKeyPair keyPair = Dilithium.generateKeyPair(DilithiumParameterSpec.LEVEL3, randomSeed());  // Level2 or Level5 can be used as well
  
  final Uint8List validMsg = utf8.encode("Valid Message");
  final Uint8List signature = Dilithium.sign(keyPair.privateKey, validMsg);

  bool isValid = Dilithium.verify(keyPair.publicKey, signature, validMsg);
  assert(isValid);

  final modifiedMsg = utf8.encode("Modified Message");
  isValid = Dilithium.verify(keyPair.publicKey, signature, modifiedMsg);
  assert(!isValid);

  Uint8List encodedPublicKey = keyPair.publicKey.serialize();
  Uint8List encodedPrivateKey = keyPair.privateKey.serialize();

  print("Private Key:"); print(encodedPrivateKey);
  print("\nPublic Key:"); print(encodedPublicKey);

  DilithiumPublicKey reinstantiatedPublicKey = DilithiumPublicKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPublicKey);
  DilithiumPrivateKey reinstantiatedPrivateKey = DilithiumPrivateKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPrivateKey);

  final Uint8List recovedSignature = Dilithium.sign(reinstantiatedPrivateKey, validMsg);

  isValid = Dilithium.verify(reinstantiatedPublicKey, recovedSignature, utf8.encode("Recovering Message"));
  assert(isValid);
}



