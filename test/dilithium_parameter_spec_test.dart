
import 'package:dilithium/dilithium.dart';
import 'package:test/test.dart';

void main() {
  test('getSpecForSecurityLevel', () {
    expect(DilithiumParameterSpec.getSpecForSecurityLevel(2), DilithiumParameterSpec.LEVEL2);
    expect(DilithiumParameterSpec.getSpecForSecurityLevel(3), DilithiumParameterSpec.LEVEL3);
    expect(DilithiumParameterSpec.getSpecForSecurityLevel(5), DilithiumParameterSpec.LEVEL5);
    expect(() => DilithiumParameterSpec.getSpecForSecurityLevel(4), throwsA(isA<UnsupportedError>()));
  });

  test('toString', () {
    expect(DilithiumParameterSpec.LEVEL2.toString(), 'Dilithium level 2 parameters');
    expect(DilithiumParameterSpec.LEVEL3.toString(), 'Dilithium level 3 parameters');
    expect(DilithiumParameterSpec.LEVEL5.toString(), 'Dilithium level 5 parameters');
  });
}