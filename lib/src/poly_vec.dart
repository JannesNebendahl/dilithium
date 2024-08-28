import 'dart:typed_data';
import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:dilithium_crypto/src/poly.dart';

/// Represents a vector of `Poly` objects and provides various operations on them.
class PolyVec {
  /// The list of `Poly` objects contained in this vector.
  List<Poly> poly;

  /// Creates a `PolyVec` of the specified `size` with empty polynomials (polynomials with coefficients of 0) initializing all `Poly` objects to zero.
  PolyVec(int size) : poly = List<Poly>.filled(size, Poly(0));

  /// Private constructor used internally for creating a `PolyVec` with an existing list of `Poly` objects.
  PolyVec._(this.poly);

  /// Returns the length of the `PolyVec`.
  int get length => poly.length;

  /// Adds another `PolyVec` to this one and returns the result.
  /// 
  /// Throws an `PolyVectorLengthMismatch` if the lengths of the two vectors do not match.
  PolyVec add(PolyVec other) {
    if (other.length != length) {
      throw PolyVectorLengthMismatch(other.length, length);
    }
    final newPoly = List<Poly>.generate(poly.length, (i) => poly[i].add(other.poly[i]));
    return PolyVec._(newPoly);
  }

  /// Subtracts another `PolyVec` from this one and returns the result.
  /// 
  /// Throws an `PolyVectorLengthMismatch` if the lengths of the two vectors do not match.
  PolyVec sub(PolyVec other) {
    if (other.length != length) {
      throw PolyVectorLengthMismatch(other.length, length);
    }
    final newPoly = List<Poly>.generate(poly.length, (i) => poly[i].sub(other.poly[i]));
    return PolyVec._(newPoly);
  }

  /// Generates a random `PolyVec` using the given parameters.
  /// 
  /// Parameters:
  /// - `rho`: The seed used for randomness
  /// - `eta`: The parameter determining the range of coefficients.
  ///          Must be either 2 or 4. 
  /// - `length`: The number of `Poly` objects
  /// - `nonce`: A unique value to ensure different outputs for the same `rho`.
  /// 
  /// Returns:
  /// - A random `PolyVec` object.
  ///
  /// Throws:
  /// - `IllegalEta` if `eta` is not 2 or 4.
  static PolyVec randomVec(Uint8List rho, int eta, int length, int nonce) {
    if (eta != 2 && eta != 4) {
      throw IllegalEta(eta);
    }
    PolyVec pv = PolyVec(length);
    for (int i = 0; i < length; i++) {
      pv.poly[i] = Poly.genRandom(rho, eta, nonce++);
    }
    return pv;
  }

  /// Applies the Number Theoretic Transform (NTT) to each `Poly` in the vector.
  /// 
  /// Returns:
  /// - A new `PolyVec` object with the transformed `Poly` objects.
  PolyVec ntt() {
    final newPoly = poly.map((p) => p.ntt()).toList();
    return PolyVec._(newPoly);
  }

  /// Applies the pointwise Montgomery multiplication with a given `Poly` to each `Poly` in the vector.
  /// 
  /// Parameters:
  /// - `u`: The `Poly` object to multiply with.
  /// 
  /// Returns:
  /// - A new `PolyVec` object with the multiplied `Poly` object.
  PolyVec pointwiseMontgomery(Poly u) {
    final newPoly = poly.map((x) => u.pointwiseMontgomery(x)).toList();
    return PolyVec._(newPoly);
  }

  /// Multiplies a matrix of `PolyVec` objects pointwise using the Montgomery method.
  /// 
  /// Parameters:
  /// - `M`: A list of `PolyVec` objects representing the matrix.
  /// 
  /// Returns:
  /// - A new `PolyVec` object with the multiplied matrix.
  PolyVec mulMatrixPointwiseMontgomery(List<PolyVec> M) {
    PolyVec pv = PolyVec(M.length);
    for (int i = 0; i < M.length; i++) {
      pv.poly[i] = _pointwiseAccMontgomery(M[i], this);
    }
    return pv;
  }

  /// Helper method for pointwise accumulation using the Montgomery method.
  Poly _pointwiseAccMontgomery(PolyVec u, PolyVec v) {
    Poly w = u.poly[0].pointwiseMontgomery(v.poly[0]);
    for (int i = 1; i < v.length; i++) {
      Poly t = u.poly[i].pointwiseMontgomery(v.poly[i]);
      w = w.add(t);
    }
    return w;
  }

  /// Reduces each `Poly` in the vector by modulo `Dilithium.Q`.
  void reduce() {
    for (var p in poly) {
      p.reduce();
    }
  }

  /// Applies the inverse NTT to each `Poly` in the vector and converts to Montgomery form.
  void invnttTomont() {
    for (var p in poly) {
      p.invnttTomont();
    }
  }

  /// Adds `Dilithium.Q` to each `Poly` in the vector and reduces by modulo `Dilithium.Q`.
  void caddq() {
    for (var p in poly) {
      p.caddq();
    }
  }

  /// Applies the power rounding to each `Poly` in the vector.
  /// 
  /// Returns: A list of two `PolyVec` objects
  /// - index 0: Vector containing the rounded polynomials
  /// - index 1: Vector containing the remaining polynomials
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

  /// Generates a random `PolyVec` using the given parameters and Gamma1 distribution.
  /// 
  /// Parameters:
  /// - `seed`: The seed used for randomness
  /// - `length`: The number of `Poly` objects
  /// - `gamma1`: The upper bound for the coefficients (should be 2^17 or 2^19).
  /// - `nonce`: A unique value to ensure different outputs for the same `seed`.
  /// 
  /// Returns:
  /// - A random `PolyVec` object.
  /// 
  /// Throws:
  /// - `IllegalGamma1` if `gamma1` is not 2^17 or 2^19.
  static PolyVec randomVecGamma1(Uint8List seed, int length, int gamma1, int nonce) {
    if(gamma1 != (1 << 17) && gamma1 != (1 << 19)) {
      throw IllegalGamma1(gamma1);
    }

    PolyVec z = PolyVec(length);
    for (int i = 0; i < length; i++) {
      z.poly[i] = Poly.genRandomGamma1(seed, length * nonce + i, Dilithium.N, gamma1);
    }
    return z;
  }

  /// Decomposes each `Poly` in the vector using the given Gamma2 parameter.
  /// 
  /// Parameters:
  /// - `gamma2`: The value of gamma2 (either (Dilithium.Q - 1) / 32 or (Dilithium.Q - 1) / 88).
  /// 
  /// Returns: A list of two `PolyVec` objects
  /// - index 0: Vector containing the rounded polynomials
  /// - index 1: Vector containing the large parts of the polynomials
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

  /// Checks if any `Poly` in the vector exceeds the given bound.
  /// 
  /// Returns:
  /// - `true` if any `Poly` exceeds the bound
  /// - `false` otherwise
  bool chknorm(int bound) {
    for (Poly p in poly) {
      if (p.chknorm(bound)) {
        return true;
      }
    }
    return false;
  }

  /// Shifts each `Poly` in the vector to the left by `Dilithium.D` bits.
  PolyVec shift() {
    final newPoly = poly.map((p) => p.shiftl()).toList();
    return PolyVec._(newPoly);
  }
}