import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/dart_utils.dart';
import 'package:pointycastle/digests/shake.dart';

/// Represents a polynomial with integer coefficients modulo `Dilithium.Q`.
class Poly {
  /// coefficients of the polynomial
  List<int> coef;

  /// creates a polynomial with `n` coefficients initialized to 0.
  Poly(int n) : coef = List.filled(n, 0) {}

  /// Adds two polynomials element-wise modulo `Dilithium.Q`.
  ///
  /// This method adds the coefficients of the current polynomial to the 
  /// corresponding coefficients of the `other` polynomial, storing the result
  /// in a new polynomial.
  ///
  /// Parameters:
  /// - `other`: The polynomial to be added.
  ///
  /// Returns:
  /// - A new polynomial with the element-wise sum of coefficients.
  Poly add(Poly other) {
    Poly res = Poly(coef.length);
    for (int i = 0; i < coef.length; i++) {
      res.coef[i] = (coef[i] + other.coef[i]) % Dilithium.Q;
    }
    return res;
  }

  /// Subtracts another polynomial from this polynomial element-wise modulo `Dilithium.Q`.
  ///
  /// This method subtracts the coefficients of the `other` polynomial from the 
  /// corresponding coefficients of the current polynomial, storing the result
  /// in a new polynomial.
  ///
  /// Parameters:
  /// - `other`: The polynomial to be subtracted.
  ///
  /// Returns:
  /// - A new polynomial with the element-wise difference of coefficients.
  Poly sub(Poly other) {
    Poly res = Poly(coef.length);
    for (int i = 0; i < coef.length; i++) {
      res.coef[i] = (coef[i] - other.coef[i]) % Dilithium.Q;
    }
    return res;
  }

  /// Returns a string representation of the polynomial.
  ///
  /// The string format is a comma-separated list of coefficients enclosed in square brackets.
  ///
  /// Returns:
  /// - A string representation of the polynomial.
  @override
  String toString() {
    return '[${coef.join(', ')}]';
  }

  /// Generates a random polynomial using the provided parameters.
  ///
  /// This method generates a polynomial with coefficients sampled uniformly
  /// from the set {0, ..., eta - 1}, using a SHAKE-256 based pseudorandom
  /// number generator seeded with `rho` and `nonce`.
  ///
  /// Parameters:
  /// - `rho`: A 32-byte seed used for randomness.
  /// - `eta`: The parameter determining the range of coefficients.
  ///          Must be either 2 or 4.
  /// - `nonce`: A unique value to ensure different outputs for the same `rho`.
  ///
  /// Returns:
  /// - A polynomial with coefficients in the range determined by `eta`.
  ///
  /// Throws:
  /// - `ArgumentError` if `eta` is not 2 or 4.
  static Poly genRandom(Uint8List rho, int eta, int nonce) {
    int POLY_UNIFORM_ETA_NBLOCKS;
    if (eta == 2) {
      POLY_UNIFORM_ETA_NBLOCKS = ((136 + Dilithium.STREAM256_BLOCKBYTES - 1) ~/ Dilithium.STREAM256_BLOCKBYTES);
    } else if (eta == 4) {
      POLY_UNIFORM_ETA_NBLOCKS = ((227 + Dilithium.STREAM256_BLOCKBYTES - 1) ~/ Dilithium.STREAM256_BLOCKBYTES);
    } else {
      throw ArgumentError('Illegal eta: $eta (eta must be 2 or 4)');
    }

    int ctr;
    var s = SHAKEDigest(256);
    s.update(rho, 0, rho.length);

    var non = Uint8List(2);
    non[0] = (nonce & 0xFF);
    non[1] = ((nonce >> 8) & 0xFF);
    s.update(non, 0, 2);

    var bb = Uint8List(POLY_UNIFORM_ETA_NBLOCKS * Dilithium.STREAM256_BLOCKBYTES);
    s.doOutput(bb, 0, bb.length);

    Poly pre = Poly(Dilithium.N);
    ctr = _rej_eta(eta, pre.coef, 0, Dilithium.N, bb, bb.length);

    while (ctr < Dilithium.N) {
      s.doOutput(bb, 0, Dilithium.STREAM256_BLOCKBYTES);
      ctr += _rej_eta(eta, pre.coef, ctr, Dilithium.N - ctr, bb, Dilithium.STREAM256_BLOCKBYTES);
    }
    return pre;
  }

  static int _rej_eta(int eta, List<int> coef, int off, int len, Uint8List buf, int buflen) {
    int ctr = 0, pos = 0;
    int t0, t1;

    if (eta == 2) {
      while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = (buf[pos++] >> 4) & 0x0F;
        if (t0 < 15) {
          t0 = t0 - ((205 * t0) >> 10) * 5;
          coef[off + ctr++] = 2 - t0;
        }
        if (t1 < 15 && ctr < len) {
          t1 = t1 - ((205 * t1) >> 10) * 5;
          coef[off + ctr++] = 2 - t1;
        }
      }
    } else {
      while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = (buf[pos++] >> 4) & 0x0F;
        if (t0 < 9) coef[off + ctr++] = 4 - t0;
        if (t1 < 9 && ctr < len) coef[off + ctr++] = 4 - t1;
      }
    }

    return ctr;
  }

  /// Computes the Number Theoretic Transform (NTT) of the polynomial.
  ///
  /// This method performs the in-place Cooley-Tukey NTT on the polynomial's
  /// coefficients. The NTT is a number-theoretic analogue of the Fast Fourier
  /// Transform (FFT) and is used for efficient polynomial multiplication
  /// in finite fields.
  ///
  /// Returns:
  /// - A new polynomial which is the NTT of the current polynomial.
  Poly ntt() {
    Poly ret = Poly(coef.length);
    for (int i = 0; i < coef.length; i++) {
      ret.coef[i] = coef[i];
    }
    int len, start, j, k;
    int zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
      for (start = 0; start < Dilithium.N; start = j + len) {
        zeta = Dilithium.zetas[++k];
        for (j = start; j < start + len; ++j) {
          t = montgomery_reduce(zeta * ret.coef[j + len]);
          ret.coef[j + len] = ret.coef[j] - t;
          ret.coef[j] = ret.coef[j] + t;
        }
      }
    }
    return ret;
  }

  /// Performs Montgomery reduction on an integer.
  ///
  /// This method reduces an integer modulo a given modulus using the Montgomery
  /// reduction technique. It is used to efficiently compute modular reductions,
  /// particularly in cryptographic algorithms.
  ///
  /// Parameters:
  /// - `a`: The integer to be reduced.
  ///
  /// Returns:
  /// - The reduced integer.
  static int montgomery_reduce(int a) {
    int t0 = DartUtils.toJavaInt32(a * Dilithium.QINV & 0xFFFFFFFF);
    int t1 = ((a - t0 * Dilithium.Q) >> 32) & 0xFFFFFFFF;
    return DartUtils.toJavaInt32(t1);
  }


  /// Generates a polynomial with coefficients uniformly sampled from a bounded set.
  ///
  /// This function generates a polynomial with coefficients that are uniformly
  /// random integers modulo a prime `Dilithium.Q`, using a SHAKE128-based PRNG.
  ///
  /// Parameters:
  /// - `rho`: Byte array serving as the input for the SHAKE128 hash function.
  /// - `nonce`: Nonce value for domain separation in the hash function.
  ///
  /// Returns:
  /// - A polynomial `Poly` with coefficients sampled uniformly at random.
  static Poly genUniformRandom(Uint8List rho, int nonce) {
    final int POLY_UNIFORM_NBLOCKS = ((768 + Dilithium.STREAM128_BLOCKBYTES - 1) ~/ Dilithium.STREAM128_BLOCKBYTES);
    int ctr, off;
    int buflen = POLY_UNIFORM_NBLOCKS * Dilithium.STREAM128_BLOCKBYTES;
    var buf = Uint8List(buflen + 2);

    var s = SHAKEDigest(128);
    s.update(rho, 0, rho.length);

    var non = Uint8List(2);
    non[0] = (nonce & 0xFF);
    non[1] = ((nonce >> 8) & 0xFF);
    s.update(non, 0, 2);
    s.doOutput(buf, 0, buflen);

    Poly pre = Poly(Dilithium.N);
    ctr = _rej_uniform(pre.coef, 0, Dilithium.N, buf, buflen);

    while (ctr < Dilithium.N) {
      off = buflen % 3;
      for (int i = 0; i < off; i++) buf[i] = buf[buflen - off + i];
      s.doOutput(buf, off, Dilithium.STREAM128_BLOCKBYTES);
      buflen = Dilithium.STREAM128_BLOCKBYTES + off;
      ctr += _rej_uniform(pre.coef, ctr, Dilithium.N - ctr, buf, buflen);
    }
    return pre;
  }

  static int _rej_uniform(List<int> coef, int off, int len, Uint8List buf, int buflen) {
    int ctr = 0, pos = 0;
    int t;

    while (ctr < len && pos + 3 <= buflen) {
      t = buf[pos++] & 0xFF;
      t |= (buf[pos++] & 0xFF) << 8;
      t |= (buf[pos++] & 0xFF) << 16;
      t &= 0x7FFFFF;

      if (t < Dilithium.Q) coef[off + ctr++] = t;
    }
    return ctr;
  }

  /// Performs pointwise multiplication of this polynomial by another polynomial
  /// using Montgomery reduction.
  ///
  /// This function multiplies each coefficient of `this` polynomial by the
  /// corresponding coefficient of `other` polynomial, reduces the result
  /// modulo `Dilithium.Q` using Montgomery reduction, and stores the result
  /// in a new polynomial `c`.
  ///
  /// Parameters:
  /// - `other`: The polynomial to multiply with.
  ///
  /// Returns:
  /// - A new polynomial `c` resulting from the pointwise multiplication
  ///   and Montgomery reduction.
  Poly pointwiseMontgomery(Poly other) {
    Poly c = Poly(Dilithium.N);
    for (int i = 0; i < Dilithium.N; i++) {
      c.coef[i] = montgomery_reduce(coef[i] * other.coef[i]);
    }
    return c;
  }
  
  /// Reduces each coefficient of this polynomial modulo `Dilithium.Q`.
  ///
  /// This function reduces each coefficient of the polynomial `coef` modulo
  /// `Dilithium.Q` and updates the coefficients in place.
  void reduce() {
    for (int i = 0; i < Dilithium.N; i++) {
      coef[i] = _reduce32(coef[i]);
    }
  }

  static int _reduce32(int a) {
    int t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * Dilithium.Q;
    return t;
  }

  /// Applies inverse NTT (Number Theoretic Transform) to the polynomial `coef`,
  /// followed by Montgomery reduction.
  ///
  /// This function computes the inverse NTT of the polynomial `coef` using
  /// precomputed `Dilithium.zetas`, then performs Montgomery reduction on the
  /// coefficients. It transforms `coef` in place.
  void invnttTomont() {
    int start, len, j, k;
    int t, zeta;
    final int f = 41978; // mont^2/256

    k = 256;
    for (len = 1; len < Dilithium.N; len <<= 1) {
      for (start = 0; start < Dilithium.N; start = j + len) {
        zeta = -Dilithium.zetas[--k];
        for (j = start; j < start + len; ++j) {
          t = coef[j];
          coef[j] = t + coef[j + len];
          coef[j + len] = t - coef[j + len];
          coef[j + len] = montgomery_reduce(zeta * coef[j + len]);
        }
      }
    }

    for (j = 0; j < Dilithium.N; ++j) {
      coef[j] = montgomery_reduce(f * coef[j]);
    }
  }

  /// Adds `Dilithium.Q` to each coefficient of the polynomial `coef`
  /// and reduces modulo `Dilithium.Q`.
  ///
  /// This function ensures that each coefficient of the polynomial `coef`
  /// is in the range [0, `Dilithium.Q`).
  void caddq() {
    for (int i = 0; i < coef.length; i++) {
      coef[i] = _caddq(coef[i]);
    }
  }

  int _caddq(int a) {
    a += Dilithium.Q;
    a -= (a >> 30) * Dilithium.Q;
    return a;
  }

  /// Performs power rounding on the coefficients of the polynomial.
  ///
  /// Returns: A list containing two polynomials.
  /// - index 0: The polynomial containing the rounded coefficients.
  /// - index 1: The polynomial containing the remaining coefficients.
  List<Poly> powerRound() {
    List<Poly> pr = [Poly(Dilithium.N), Poly(Dilithium.N)];

    for (int i = 0; i < coef.length; i++) {
      int a = coef[i];
      pr[1].coef[i] = (a + (1 << (Dilithium.D - 1)) - 1) >> Dilithium.D;
      pr[0].coef[i] = a - (pr[1].coef[i] << Dilithium.D);
    }
    return pr;
  }

  /// Packs the coefficients of the polynomial `coef` into a byte array `r`
  /// starting at the specified offset `off`.
  ///
  /// Each group of 4 coefficients from `coef` is packed into 5 bytes in `r`,
  /// according to the Dilithium packing scheme:
  /// - Byte 0: Bits 0-7 of coef[0]
  /// - Byte 1: Bits 8-9 of coef[0], Bits 0-1 of coef[1]
  /// - Byte 2: Bits 2-7 of coef[1], Bits 0-3 of coef[2]
  /// - Byte 3: Bits 4-7 of coef[2], Bits 0-5 of coef[3]
  /// - Byte 4: Bits 6-7 of coef[3]
  ///
  /// Parameters:
  /// - `r`: The byte array to pack coefficients into.
  /// - `off`: The starting offset in `r` where packing begins.
  void t1pack(Uint8List r, int off) {
    for (int i = 0; i < Dilithium.N / 4; i++) {
      r[5 * i + 0 + off] = (coef[4 * i + 0] >> 0) & 0xFF;
      r[5 * i + 1 + off] = (coef[4 * i + 0] >> 8) | ((coef[4 * i + 1] << 2) & 0xFF);
      r[5 * i + 2 + off] = (coef[4 * i + 1] >> 6) | ((coef[4 * i + 2] << 4) & 0xFF);
      r[5 * i + 3 + off] = (coef[4 * i + 2] >> 4) | ((coef[4 * i + 3] << 6) & 0xFF);
      r[5 * i + 4 + off] = (coef[4 * i + 3] >> 2) & 0xFF;
    }
  }

  /// Packs the coefficients of the polynomial into a buffer `buf` based on the value of `eta`.
  ///
  /// For `eta = 2`:
  /// - Computes the difference `eta - coef[8 * i + j]` for each j in [0, 1, ..., 7].
  /// - Packs these differences into `buf` in a format suitable for eta = 2. Each 24-bit block in `buf`
  ///   encodes three differences using bitwise operations.
  ///
  /// For `eta = 4`:
  /// - Computes the difference `eta - coef[2 * i + j]` for each j in [0, 1].
  /// - Packs these differences into `buf` in a format suitable for eta = 4. Each byte in `buf` holds two
  ///   differences encoded using bitwise operations.
  ///
  /// Throws [ArgumentError] if `eta` is neither 2 nor 4.
  ///
  /// Parameters:
  /// - `eta`: The value of eta (2 or 4).
  /// - `buf`: The buffer to store the packed coefficients.
  /// - `off`: The offset in the buffer `buf` where packing starts.
  void etapack(int eta, Uint8List buf, int off) {
    List<int> t = List.filled(8, 0);
    if (eta == 2) {
      for (int i = 0; i < Dilithium.N / 8; i++) {
        t[0] = eta - coef[8 * i + 0];
        t[1] = eta - coef[8 * i + 1];
        t[2] = eta - coef[8 * i + 2];
        t[3] = eta - coef[8 * i + 3];
        t[4] = eta - coef[8 * i + 4];
        t[5] = eta - coef[8 * i + 5];
        t[6] = eta - coef[8 * i + 6];
        t[7] = eta - coef[8 * i + 7];

        buf[off + 3 * i + 0] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) & 0xFF;
        buf[off + 3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF;
        buf[off + 3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF;
      }
    } else if (eta == 4) {
      for (int i = 0; i < Dilithium.N / 2; i++) {
        t[0] = eta - coef[2 * i + 0];
        t[1] = eta - coef[2 * i + 1];
        buf[off + i] = (t[0] | (t[1] << 4)) & 0xFF;
      }
    } else {
      throw ArgumentError("Illegal eta: $eta");
    }
  }

  /// Packs the coefficients of the polynomial into a buffer `buf` in a specific format.
  ///
  /// For each group of 8 coefficients in the polynomial:
  /// - Computes `t[i] = (1 << (Dilithium.D - 1)) - coef[8 * i + j]` for j in [0, 1, ..., 7].
  /// - Packs the results into `buf` in a structured manner using 13 bytes per group. Each coefficient
  ///   is represented using a combination of bitwise operations to fit into the specified 13-byte format.
  ///
  /// Parameters:
  /// - `buf`: The buffer to store the packed coefficients.
  /// - `off`: The offset in the buffer `buf` where packing starts.
  void t0pack(Uint8List buf, int off) {
    List<int> t = List.filled(8, 0);

    for (int i = 0; i < Dilithium.N / 8; i++) {
      t[0] = (1 << (Dilithium.D - 1)) - coef[8 * i + 0];
      t[1] = (1 << (Dilithium.D - 1)) - coef[8 * i + 1];
      t[2] = (1 << (Dilithium.D - 1)) - coef[8 * i + 2];
      t[3] = (1 << (Dilithium.D - 1)) - coef[8 * i + 3];
      t[4] = (1 << (Dilithium.D - 1)) - coef[8 * i + 4];
      t[5] = (1 << (Dilithium.D - 1)) - coef[8 * i + 5];
      t[6] = (1 << (Dilithium.D - 1)) - coef[8 * i + 6];
      t[7] = (1 << (Dilithium.D - 1)) - coef[8 * i + 7];

      buf[off + 13 * i + 0] = t[0] & 0xFF;
      buf[off + 13 * i + 1] = (t[0] >> 8) & 0xFF;
      buf[off + 13 * i + 1] |= (t[1] << 5) & 0xFF;
      buf[off + 13 * i + 2] = (t[1] >> 3) & 0xFF;
      buf[off + 13 * i + 3] = (t[1] >> 11) & 0xFF;
      buf[off + 13 * i + 3] |= (t[2] << 2) & 0xFF;
      buf[off + 13 * i + 4] = (t[2] >> 6) & 0xFF;
      buf[off + 13 * i + 4] |= (t[3] << 7) & 0xFF;
      buf[off + 13 * i + 5] = (t[3] >> 1) & 0xFF;
      buf[off + 13 * i + 6] = (t[3] >> 9) & 0xFF;
      buf[off + 13 * i + 6] |= (t[4] << 4) & 0xFF;
      buf[off + 13 * i + 7] = (t[4] >> 4) & 0xFF;
      buf[off + 13 * i + 8] = (t[4] >> 12) & 0xFF;
      buf[off + 13 * i + 8] |= (t[5] << 1) & 0xFF;
      buf[off + 13 * i + 9] = (t[5] >> 7) & 0xFF;
      buf[off + 13 * i + 9] |= (t[6] << 6) & 0xFF;
      buf[off + 13 * i + 10] = (t[6] >> 2) & 0xFF;
      buf[off + 13 * i + 11] = (t[6] >> 10) & 0xFF;
      buf[off + 13 * i + 11] |= (t[7] << 3) & 0xFF;
      buf[off + 13 * i + 12] = (t[7] >> 5) & 0xFF;
    }
  }

  /// Generates a random polynomial `pre` with coefficients in the range [0, gamma1)
  /// using the SHAKE256 digest of `seed` and `nonce`.
  ///
  /// Parameters:
  /// - `seed`: The seed used for randomness.
  /// - `nonce`: The nonce to diversify the output.
  /// - `N`: The number of coefficients in the polynomial.
  /// - `gamma1`: The upper bound for the coefficients (should be 2^17 or 2^19).
  ///
  /// Returns:
  /// - A polynomial `pre` with coefficients sampled from the distribution Gamma1.
  ///
  /// Throws [ArgumentError] if `gamma1` is not 2^17 or 2^19.
  static Poly genRandomGamma1(Uint8List seed, int nonce, int N, int gamma1) {
    Poly pre = Poly(N);
    Uint8List buf = Uint8List(Dilithium.POLY_UNIFORM_GAMMA1_NBLOCKS * Dilithium.STREAM256_BLOCKBYTES);
    final s = SHAKEDigest(256);
    s.update(seed, 0, seed.length);

    Uint8List non = Uint8List(2);
    non[0] = (nonce & 0xFF);
    non[1] = ((nonce >> 8) & 0xFF);
    s.update(non, 0, non.length);
    s.doOutput(buf, 0, buf.length);

    if (gamma1 == (1 << 17)) {
      for (int i = 0; i < N / 4; i++) {
        pre.coef[4 * i + 0] = (buf[9 * i + 0] & 0xFF) |
                              ((buf[9 * i + 1] & 0xFF) << 8) |
                              ((buf[9 * i + 2] & 0xFF) << 16) & 0x3FFFF;
        pre.coef[4 * i + 0] = gamma1 - pre.coef[4 * i + 0];

        pre.coef[4 * i + 1] = ((buf[9 * i + 2] & 0xFF) >> 2) |
                              ((buf[9 * i + 3] & 0xFF) << 6) |
                              ((buf[9 * i + 4] & 0xFF) << 14) & 0x3FFFF;
        pre.coef[4 * i + 1] = gamma1 - pre.coef[4 * i + 1];

        pre.coef[4 * i + 2] = ((buf[9 * i + 4] & 0xFF) >> 4) |
                              ((buf[9 * i + 5] & 0xFF) << 4) |
                              ((buf[9 * i + 6] & 0xFF) << 12) & 0x3FFFF;
        pre.coef[4 * i + 2] = gamma1 - pre.coef[4 * i + 2];

        pre.coef[4 * i + 3] = ((buf[9 * i + 6] & 0xFF) >> 6) |
                              ((buf[9 * i + 7] & 0xFF) << 2) |
                              ((buf[9 * i + 8] & 0xFF) << 10) & 0x3FFFF;
        pre.coef[4 * i + 3] = gamma1 - pre.coef[4 * i + 3];
      }
    } else if (gamma1 == (1 << 19)) {
      for (int i = 0; i < N / 2; i++) {
        pre.coef[2 * i + 0] = (buf[5 * i + 0] & 0xFF) |
                              ((buf[5 * i + 1] & 0xFF) << 8) |
                              ((buf[5 * i + 2] & 0xFF) << 16) & 0xFFFFF;
        pre.coef[2 * i + 0] = gamma1 - pre.coef[2 * i + 0];

        pre.coef[2 * i + 1] = ((buf[5 * i + 2] & 0xFF) >> 4) |
                              ((buf[5 * i + 3] & 0xFF) << 4) |
                              ((buf[5 * i + 4] & 0xFF) << 12) & 0xFFFFF;
        pre.coef[2 * i + 1] = gamma1 - pre.coef[2 * i + 1];
      }
    } else {
      throw ArgumentError("Invalid gamma1: $gamma1");
    }

    return pre;
  }


  /// Decomposes each coefficient of the polynomial into two parts based on the value of gamma2.  
  /// 
  /// Parameters:
  /// - `gamma2`: The value of gamma2 (either (Dilithium.Q - 1) / 32 or (Dilithium.Q - 1) / 88).
  /// 
  /// Returns: A list containing two polynomials.
  /// - index 0: The rounded remainder polynomial
  /// - index 1: The large polynomial part
  /// 
  /// Throws [ArgumentError] if `gamma2` is neither (Dilithium.Q - 1) / 32 nor (Dilithium.Q - 1) / 88.
  List<Poly> decompose(final int gamma2) {
    List<Poly> pr = [Poly(Dilithium.N), Poly(Dilithium.N)];

    for (int i = 0; i < coef.length; i++) {
      int a = coef[i];
      int a1 = (a + 127) >> 7;
      if (gamma2 == (Dilithium.Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
      } else if (gamma2 == (Dilithium.Q - 1) / 88) {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
      } else {
        throw ArgumentError("Invalid gamma2: $gamma2");
      }
      pr[0].coef[i] = a - a1 * 2 * gamma2;
      pr[0].coef[i] -= (((Dilithium.Q - 1) ~/ 2 - pr[0].coef[i]) >> 31) & Dilithium.Q;
      pr[1].coef[i] = a1;
    }
    return pr;
  }

  /// Packs the coefficients of the polynomial `coef` into `buf` based on `gamma2`.
  ///
  /// Parameters:
  /// - `gamma2`: The value of gamma2 (either (Dilithium.Q - 1) / 88 or (Dilithium.Q - 1) / 32).
  /// - `buf`: The byte array where coefficients will be packed.
  /// - `off`: The offset in `buf` where packing should start.
  ///
  /// Throws [ArgumentError] if `gamma2` is neither (Dilithium.Q - 1) / 88 nor (Dilithium.Q - 1) / 32.
  void w1pack(int gamma2, Uint8List buf, int off) {
    if (gamma2 == (Dilithium.Q - 1) / 88) {
      for (int i = 0; i < Dilithium.N / 4; i++) {
        buf[off + 3 * i + 0] = (coef[4 * i + 0]) & 0xFF;
        buf[off + 3 * i + 0] |= (coef[4 * i + 1] << 6) & 0xFF;
        buf[off + 3 * i + 1] = (coef[4 * i + 1] >> 2) & 0xFF;
        buf[off + 3 * i + 1] |= (coef[4 * i + 2] << 4) & 0xFF;
        buf[off + 3 * i + 2] = (coef[4 * i + 2] >> 4) & 0xFF;
        buf[off + 3 * i + 2] |= (coef[4 * i + 3] << 2) & 0xFF;
      }
    } else if (gamma2 == (Dilithium.Q - 1) / 32) {
      for (int i = 0; i < Dilithium.N / 2; i++) {
        buf[off + i] = (coef[2 * i + 0] | (coef[2 * i + 1] << 4)) & 0xFF;
      }
    } else {
      throw ArgumentError("Invalid gamma2: $gamma2");
    }
  }

  /// Checks if the norm of the polynomial `coef` exceeds the specified threshold `B`.
  ///
  /// Parameters:
  /// - `B`: The threshold value to compare against.
  ///
  /// Returns:
  /// - `true` if the norm of `coef` exceeds `B`, otherwise `false`.
  bool chknorm(int B) {
    if (B > (Dilithium.Q - 1) / 8) return true;

    int t;
    for (int i = 0; i < Dilithium.N; i++) {
      t = coef[i] >> 31;
      t = coef[i] - (t & 2 * coef[i]);

      if (t >= B) {
        return true;
      }
    }
    return false;
  }

  /// Packs the coefficients of the polynomial `coef` into `sign` based on `gamma1`.
  ///
  /// Parameters:
  /// - `gamma1`: The value of gamma1 (either 2^17 or 2^19).
  /// - `sign`: The byte array where coefficients will be packed.
  /// - `off`: The offset in `sign` where packing should start.
  ///
  /// Throws [ArgumentError] if `gamma1` is neither 2^17 nor 2^19.
  void zpack(int gamma1, Uint8List sign, int off) {
    List<int> t = List.filled(4, 0);

    if (gamma1 == (1 << 17)) {
      for (int i = 0; i < Dilithium.N / 4; i++) {
        t[0] = (gamma1 - coef[4 * i + 0]) & 0xFFFFFFFF;
        t[1] = (gamma1 - coef[4 * i + 1]) & 0xFFFFFFFF;
        t[2] = (gamma1 - coef[4 * i + 2]) & 0xFFFFFFFF;
        t[3] = (gamma1 - coef[4 * i + 3]) & 0xFFFFFFFF;

        sign[off + 9 * i + 0] = (t[0]) & 0xFF;
        sign[off + 9 * i + 1] = (t[0] >> 8) & 0xFF;
        sign[off + 9 * i + 2] = (t[0] >> 16) & 0xFF;
        sign[off + 9 * i + 2] |= (t[1] << 2) & 0xFF;
        sign[off + 9 * i + 3] = (t[1] >> 6) & 0xFF;
        sign[off + 9 * i + 4] = (t[1] >> 14) & 0xFF;
        sign[off + 9 * i + 4] |= (t[2] << 4) & 0xFF;
        sign[off + 9 * i + 5] = (t[2] >> 4) & 0xFF;
        sign[off + 9 * i + 6] = (t[2] >> 12) & 0xFF;
        sign[off + 9 * i + 6] |= (t[3] << 6) & 0xFF;
        sign[off + 9 * i + 7] = (t[3] >> 2) & 0xFF;
        sign[off + 9 * i + 8] = (t[3] >> 10) & 0xFF;
      }
    } else if (gamma1 == (1 << 19)) {
      for (int i = 0; i < Dilithium.N / 2; i++) {
        t[0] = gamma1 - coef[2 * i + 0];
        t[1] = gamma1 - coef[2 * i + 1];

        sign[off + 5 * i + 0] = (t[0]) & 0xFF;
        sign[off + 5 * i + 1] = (t[0] >> 8) & 0xFF;
        sign[off + 5 * i + 2] = (t[0] >> 16) & 0xFF;
        sign[off + 5 * i + 2] |= (t[1] << 4) & 0xFF;
        sign[off + 5 * i + 3] = (t[1] >> 4) & 0xFF;
        sign[off + 5 * i + 4] = (t[1] >> 12) & 0xFF;
      }
    } else {
      throw ArgumentError("Invalid gamma1: $gamma1");
    }
  }

  /// Shifts the coefficients of the polynomial `coef` left by `Dilithium.D` bits.
  ///
  /// Returns:
  /// - A new polynomial `pr` where each coefficient is `coef[i] << Dilithium.D`.
  Poly shiftl() {
    Poly pr = Poly(Dilithium.N);
    for (int i = 0; i < Dilithium.N; i++) {
      pr.coef[i] = (coef[i] << Dilithium.D);
    }
    return pr;
  }
}



