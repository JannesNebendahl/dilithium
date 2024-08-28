import 'package:dilithium_crypto/dilithium_crypto.dart';

class DilithiumKeyPair {
  final DilithiumPublicKey publicKey;
  final DilithiumPrivateKey privateKey;

  DilithiumKeyPair(this.publicKey, this.privateKey);
}
