import 'package:dilithium/dilithium.dart';

class DilithiumKeyPair {
  final DilithiumPublicKey publicKey;
  final DilithiumPrivateKey privateKey;

  DilithiumKeyPair(this.publicKey, this.privateKey);
}