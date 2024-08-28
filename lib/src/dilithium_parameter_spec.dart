import 'package:dilithium_crypto/dilithium_crypto.dart';

class DilithiumParameterSpec {
  final int k;
  final int l;
  final int gamma1;
  final int gamma2;
  final int tau;
  final int d;
  final int chalentropy;
  final int eta;
  final int beta;
  final int omega;
  final String name;

  const DilithiumParameterSpec._(
    this.name,
    this.k,
    this.l,
    this.gamma1,
    this.gamma2,
    this.tau,
    this.d,
    this.chalentropy,
    this.eta,
    this.beta,
    this.omega,
  );

  static const DilithiumParameterSpec LEVEL2 = DilithiumParameterSpec._(
    'Dilithium level 2 parameters', // Name
    4,                              // k
    4,                              // l
    1 << 17,                        // gamma1
    (Dilithium.Q - 1) ~/ 88,        // gamma2
    39,                             // tau
    13,                             // d
    192,                            // chalentropy
    2,                              // eta
    78,                             // beta
    80,                             // omega
  );

  static const DilithiumParameterSpec LEVEL3 = DilithiumParameterSpec._(
    'Dilithium level 3 parameters', // Name
    6,                              // k
    5,                              // l
    1 << 19,                        // gamma1
    (Dilithium.Q - 1) ~/ 32,        // gamma2
    49,                             // tau
    13,                             // d
    225,                            // chalentropy
    4,                              // eta
    196,                            // beta
    55,                             // omega
  );

  static const DilithiumParameterSpec LEVEL5 = DilithiumParameterSpec._(
    'Dilithium level 5 parameters', // Name
    8,                              // k
    7,                              // l
    1 << 19,                        // gamma1
    (Dilithium.Q - 1) ~/ 32,        // gamma2
    60,                             // tau
    13,                             // d
    257,                            // chalentropy
    2,                              // eta
    120,                            // beta
    75,                             // omega
  );

  static DilithiumParameterSpec getSpecForSecurityLevel(int level) {
    switch (level) {
      case 2:
        return LEVEL2;
      case 3:
        return LEVEL3;
      case 5:
        return LEVEL5;
      default:
        throw UnsupportedError('Unsupported level: $level');
    }
  }

  @override
  String toString() {
    return name;
  }
}
