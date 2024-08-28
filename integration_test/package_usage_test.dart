import 'dart:math';
import 'dart:typed_data';
import 'package:dilithium/dilithium.dart';
import 'package:test/test.dart';

void main() {
  Uint8List randomSeed(){
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(Dilithium.SEEDBYTES, (_) => random.nextInt(256)));
  }

  void keygen(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, randomSeed());

    expect(keyPair.publicKey, isA<DilithiumPublicKey>());
    expect(keyPair.privateKey, isA<DilithiumPrivateKey>());
  }

  void signAndVerify(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, randomSeed());
    final altKeyPair = Dilithium.generateKeyPair(spec, randomSeed());

    for(int msgLength = 0; msgLength < 10; msgLength++){
      final message = Uint8List.fromList(List<int>.generate(msgLength, (_) => msgLength));

      final signature = Dilithium.sign(keyPair.privateKey, message);

      // Can verify with correct key
      expect(Dilithium.verify(keyPair.publicKey, signature, message), isTrue);

      // Cannot verify with incorrect key
      expect(Dilithium.verify(altKeyPair.publicKey, signature, message), isFalse);

      // Cannot verify with incorrect signature length
      Uint8List toShortSignature = signature.sublist(0, signature.length - 1);
      expect(Dilithium.verify(keyPair.publicKey, toShortSignature, message), isFalse);

      // Can detect any bit-level modifications of the message
      for(int modifiedByte=0; modifiedByte < msgLength; modifiedByte++){
        for(int modifiedBit=0; modifiedBit < 8; modifiedBit++){
          final modifiedMessage = message;
          modifiedMessage[modifiedByte] ^= 1 << modifiedBit;

          expect(Dilithium.verify(keyPair.publicKey, signature, modifiedMessage), isFalse);
        }
      }
    }
  }

  void useDeserializedKeys(DilithiumParameterSpec spec){
    final keyPair = Dilithium.generateKeyPair(spec, randomSeed());
    
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

  group('Algorithm (Dilithium) usage', (){
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