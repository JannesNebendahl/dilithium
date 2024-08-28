import 'package:dilithium_crypto/dilithium_crypto.dart';

/// Eta must be 2 or 4
class IllegalEta extends ArgumentError {
  IllegalEta(int eta) : super('Illegal eta: $eta');
}

/// Gamma1 must be 2^17 or 2^19
class IllegalGamma1 extends ArgumentError {
  IllegalGamma1(int gamma1) : super('Illegal gamma1: $gamma1');
}

/// Gamma2 must be (`Dilithium.Q` - 1) ~/ 88 or (`Dilithium.Q` - 1) ~/ 32
class IllegalGamma2 extends ArgumentError {
  IllegalGamma2(int gamma2) : super('Illegal gamma2: $gamma2');
}

class InvalidSeedLength extends ArgumentError {
  InvalidSeedLength(int actualLength)
      : super(
            'Invalid seed length, seed needs to be ${Dilithium.SEEDBYTES} bytes long but is $actualLength bytes long');
}

class PolyVectorLengthMismatch extends ArgumentError {
  PolyVectorLengthMismatch(int lengthA, lengthB)
      : super(
            'The lengths of the two PolyVecs do not match: $lengthA != $lengthB');
}
