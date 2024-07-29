import 'dart:math';
import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:test/test.dart';

void main() {
  Uint8List generateSeed(){
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
  }

  void keygen(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, generateSeed());

    expect(keyPair.publicKey, isA<DilithiumPublicKey>());
    expect(keyPair.privateKey, isA<DilithiumPrivateKey>());
  }

  void signAndVerify(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, generateSeed());
    final altKeyPair = Dilithium.generateKeyPair(spec, generateSeed());

    for(int i = 0; i < 10; i++){
      final message = Uint8List.fromList(List<int>.generate(i, (_) => i));

      final signature = Dilithium.sign(keyPair.privateKey, message);

      // Can verify with correct key
      expect(Dilithium.verify(keyPair.publicKey, signature, message), isTrue);

      // Cannot verify with incorrect key
      expect(Dilithium.verify(altKeyPair.publicKey, signature, message), isFalse);

      // Can detect any bit-level modifications of the message
      for(int j=0; j < i; j++){
        for(int k=0; k < 8; k++){
          final modifiedMessage = message;
          modifiedMessage[j] ^= 1 << k;

          expect(Dilithium.verify(keyPair.publicKey, signature, modifiedMessage), isFalse);
        }
      }
    }
  }

  void useDeserializedKeys(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, generateSeed());
    
    final message = Uint8List.fromList([0xA0, 0x16, 0xC9, 0x94]);
    final signature = Dilithium.sign(keyPair.privateKey, message);

    // Verify with reconstructed public key
    final serializedPublicKey = keyPair.publicKey.serialize();
    final reconstructedPublicKey = DilithiumPublicKey.deserialize(spec, serializedPublicKey);
    expect(Dilithium.verify(reconstructedPublicKey, signature, message), isTrue);

    // Sign with reconstructed private key
    final serializedPrivateKey = keyPair.privateKey.serialize();
    final reconstructedPrivateKey = DilithiumPrivateKey.deserialize(spec, serializedPrivateKey);
    final newMessage = Uint8List.fromList([0x1A, 0x2B, 0x3C, 0x4D]);
    final newSignature = Dilithium.sign(reconstructedPrivateKey, newMessage);

    // Verify with original public key
    expect(Dilithium.verify(keyPair.publicKey, newSignature, newMessage), isTrue);
  }

  group('End 2 End Tests', (){
    group('Dilithium 2', (){
      final spec = DilithiumParameterSpec.LEVEL2;

      test('D2 keygen',(){
        keygen(spec);
      });

      test('D2 sign and verify',(){
        signAndVerify(spec);
      });

      test('D2 use deserialized keys',(){
        useDeserializedKeys(spec);
      });
    });
    
    group('Dilithium 3', (){
      final spec = DilithiumParameterSpec.LEVEL3;

      test('D3 keygen',(){
        keygen(spec);
      });

      test('D3 sign and verify',(){
        signAndVerify(spec);
      });

      test('D3 use deserialized keys',(){
        useDeserializedKeys(spec);
      });
    });

    group('Dilithium 5', (){
      final spec = DilithiumParameterSpec.LEVEL5;

      test('D5 keygen',(){
        keygen(spec);
      });

      test('D5 sign and verify',(){
        signAndVerify(spec);
      });

      test('D5 use deserialized keys',(){
        useDeserializedKeys(spec);
      });
    });
  });
  
}