import 'package:dilithium/src/poly.dart';
import 'package:dilithium/src/poly_vec.dart';
import 'package:test/test.dart';

PolyVec mockPolyVec(List<List<int>> coef){
  PolyVec pv = PolyVec(coef.length);
  for(int i = 0; i < coef.length; i++){
    pv.poly[i] = Poly(coef[i].length)..coef = coef[i];
  }
  return pv;
}

void expectPolyVecsAreEqual(PolyVec expected, PolyVec actual){
  expect(actual.length, expected.length);
  for(int i = 0; i < expected.length; i++){
    expect(actual.poly[i].coef, expected.poly[i].coef);
  }
}