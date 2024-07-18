import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';

class PolyVec {
  List<Poly> poly;

  PolyVec(int size) : poly = List<Poly>.filled(size, Poly(0));

  PolyVec._(this.poly);

  static PolyVec randomVec(Uint8List rho, int eta, int length, int nonce) {
    PolyVec pv = PolyVec(length);
    for (int i = 0; i < length; i++) {
      pv.poly[i] = Poly.genRandom(rho, eta, nonce++);
    }
    return pv;
  }

  static PolyVec randomVecGamma1(Uint8List seed, int length, int gamma1, int nonce) {
    PolyVec z = PolyVec(length);
    for (int i = 0; i < length; i++) {
      z.poly[i] = Poly.genRandomGamma1(seed, length * nonce + i, Dilithium.N, gamma1);
    }
    return z;
  }

  PolyVec ntt() {
    final newPoly = poly.map((p) => p.ntt()).toList();
    return PolyVec._(newPoly);
  }

  void reduce() {
    poly.forEach((p) => p.reduce());
  }

  List<PolyVec> decompose(int gamma2) {
    PolyVec res0 = PolyVec(length);
    PolyVec res1 = PolyVec(length);
    for (int i = 0; i < length; i++) {
      List<Poly> r = poly[i].decompose(gamma2);
      res0.poly[i] = r[0];
      res1.poly[i] = r[1];
    }
    return [res0, res1];
  }

  void invnttTomont() {
    poly.forEach((p) => p.invnttTomont());
  }

  PolyVec add(PolyVec other) {
    final newPoly = List<Poly>.generate(poly.length, (i) => poly[i].add(other.poly[i]));
    return PolyVec._(newPoly);
  }

  PolyVec sub(PolyVec other) {
    final newPoly = List<Poly>.generate(poly.length, (i) => poly[i].sub(other.poly[i]));
    return PolyVec._(newPoly);
  }

  void caddq() {
    poly.forEach((p) => p.caddq());
  }

  PolyVec shift() {
    final newPoly = poly.map((p) => p.shiftl()).toList();
    return PolyVec._(newPoly);
  }

  List<PolyVec> powerRound() {
    PolyVec res0 = PolyVec(length);
    PolyVec res1 = PolyVec(length);
    for (int i = 0; i < poly.length; i++) {
      List<Poly> r = poly[i].powerRound();
      res0.poly[i] = r[0];
      res1.poly[i] = r[1];
    }
    return [res0, res1];
  }

  PolyVec pointwiseMontgomery(Poly u) {
    final newPoly = poly.map((x) => u.pointwiseMontgomery(x)).toList();
    return PolyVec._(newPoly);
  }

  PolyVec mulMatrixPointwiseMontgomery(List<PolyVec> M) {
    PolyVec pv = PolyVec(M.length);
    for (int i = 0; i < M.length; i++) {
      pv.poly[i] = pointwiseAccMontgomery(M[i], this);
    }
    return pv;
  }

  Poly pointwiseAccMontgomery(PolyVec u, PolyVec v) {
    Poly w = u.poly[0].pointwiseMontgomery(v.poly[0]);
    for (int i = 1; i < v.length; i++) {
      Poly t = u.poly[i].pointwiseMontgomery(v.poly[i]);
      w = w.add(t);
    }
    return w;
  }

  int get length => poly.length;

  bool chknorm(int bound) {
    for (Poly p in poly) {
      if (p.chknorm(bound)) {
        return true;
      }
    }
    return false;
  }
}