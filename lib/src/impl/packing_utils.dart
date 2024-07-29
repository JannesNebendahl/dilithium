import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/poly.dart';
import 'package:dilithium/src/impl/poly_vec.dart';


class PackingUtils {

  /// Returns the number of bytes required to pack a polynomial object with the specified `eta`.
  /// 
  /// Parameters:
  /// - `eta`: The parameter determining the compression. Valid values are 2 and 4.
  /// 
  /// Returns:
  /// - The number of bytes required to pack a polynomial object.
  ///   - If `eta` is 2, the function returns 96.
  ///   - If `eta` is 4, the function returns 128.
  /// 
  /// Throws:
  /// - `ArgumentError` if `eta` is not a valid value (not 2 or 4).
  static int getPolyEtaPackedBytes(int eta) {
    if (eta == 2) {
      return 96;
    } else if (eta == 4) {
      return 128;
    } else {
      throw IllegalEta(eta);
    }
  }

  /// Returns the number of bytes required to pack a polynomial object with the specified `gamma2`.
  /// 
  /// Parameters:
  /// - `gamma2`: The parameter determining the range of coefficients. Valid values are `(Dilithium.Q - 1) ~/ 88` and `(Dilithium.Q - 1) ~/ 32`.
  /// 
  /// Returns:
  /// - The number of bytes required to pack a polynomial object.
  ///   - If `gamma2` is `(Dilithium.Q - 1) ~/ 88`, the function returns 192.
  ///   - If `gamma2` is `(Dilithium.Q - 1) ~/ 32`, the function returns 128.
  /// 
  /// Throws:
  /// - `IllegalGamma2` if `gamma2` is not a valid value.
  static int getPolyW1PackedBytes(int gamma2) {
    if (gamma2 == (Dilithium.Q - 1) ~/ 88) {
      return 192;
    } else if (gamma2 == (Dilithium.Q - 1) ~/ 32) {
      return 128;
    } else {
      throw IllegalGamma2(gamma2);
    }
  }

  /// Returns the number of bytes required to pack a polynomial object with the specified `gamma1`.
  /// 
  /// Parameters:
  /// - `gamma1`: The parameter determining the range of coefficients. Valid values are `1 << 17` and `1 << 19`.
  /// 
  /// Returns:
  /// - The number of bytes required to pack a polynomial object.
  ///   - If `gamma1` is `1 << 17`, the function returns 576.
  ///   - If `gamma1` is `1 << 19`, the function returns 640.
  /// 
  /// Throws:
  /// - `IllegalGamma1` if `gamma1` is not a valid value.
  static int getPolyZPackedBytes(int gamma1) {
    if (gamma1 == (1 << 17)) {
      return 576;
    } else if (gamma1 == (1 << 19)) {
      return 640;
    } else {
      throw IllegalGamma1(gamma1);
    }
  }

  /// Packs the private key components into a single `Uint8List`.
  /// 
  /// Parameters:
  /// - `eta`: The parameter determining the range of coefficients.
  /// - `rho`: The seed for the first part of the secret key.
  /// - `tr`:  A `Uint8List` representing the hash of the public key.
  /// - `K`: The seed for the second part of the secret key.
  /// - `t0`: The `PolyVec` object containing the `t0` polynomials.
  /// - `s1`: The `PolyVec` object containing the `s1` polynomials.
  /// - `s2`: The `PolyVec` object containing the `s2` polynomials.
  /// 
  /// Returns:
  /// - A `Uint8List` containing the packed private key.
  /// 
  /// Throws:
  /// - `IllegalEta` if `eta` is not 2 or 4.
  static Uint8List packPrvKey(int eta, Uint8List rho, Uint8List tr, Uint8List K, PolyVec t0, PolyVec s1, PolyVec s2) {
    int off = 0;
    int POLYETA_PACKEDBYTES;
    switch (eta) {
      case 2:
        POLYETA_PACKEDBYTES = 96;
        break;
      case 4:
        POLYETA_PACKEDBYTES = 128;
        break;
      default:
        throw IllegalEta(eta);
    }

    final int CRYPTO_SECRETKEYBYTES = (2 * Dilithium.SEEDBYTES + Dilithium.CRHBYTES + s1.length * POLYETA_PACKEDBYTES + s2.length * POLYETA_PACKEDBYTES + s2.length * Dilithium.POLYT0_PACKEDBYTES);
    Uint8List buf = Uint8List(CRYPTO_SECRETKEYBYTES);

    for (int i = 0; i < Dilithium.SEEDBYTES; i++) buf[off + i] = rho[i];
    off += Dilithium.SEEDBYTES;

    for (int i = 0; i < Dilithium.SEEDBYTES; i++) buf[off + i] = K[i];
    off += Dilithium.SEEDBYTES;

    for (int i = 0; i < Dilithium.CRHBYTES; i++) buf[off + i] = tr[i];
    off += Dilithium.CRHBYTES;

    for (int i = 0; i < s1.length; i++) {
      s1.poly[i].etapack(eta, buf, off);
      off += POLYETA_PACKEDBYTES;
    }

    for (int i = 0; i < s2.length; i++) {
      s2.poly[i].etapack(eta, buf, off);
      off += POLYETA_PACKEDBYTES;
    }

    for (int i = 0; i < t0.length; i++) {
      t0.poly[i].t0pack(buf, off);
      off += Dilithium.POLYT0_PACKEDBYTES;
    }
    return buf;
  }

  /// Packs the public key components into a single `Uint8List`.
  /// 
  /// Parameters:
  /// - `rho`: The seed for the public key.
  /// - `t`: The `PolyVec` object containing the `t` polynomials.
  /// 
  /// Returns:
  /// - A `Uint8List` object containing the packed public key.
  static Uint8List packPubKey(Uint8List rho, PolyVec t) {
    int CRYPTO_PUBLICKEYBYTES = Dilithium.SEEDBYTES + t.length * Dilithium.POLYT1_PACKEDBYTES;

    Uint8List pk = Uint8List(CRYPTO_PUBLICKEYBYTES);
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) pk[i] = rho[i];

    for (int i = 0; i < t.length; i++) {
      t.poly[i].t1pack(pk, Dilithium.SEEDBYTES + i * Dilithium.POLYT1_PACKEDBYTES);
    }
    return pk;
  }

  /// Packs the signature components into a single `Uint8List`.
  /// 
  /// Parameters:
  /// - `gamma1`: The parameter determining the range of coefficients for `z`.
  /// - `omega`: The number of non-zero coefficients in `h`.
  /// - `sig`: A `Uint8List` to store the packed signature.
  /// - `c`: A `Uint8List` representing the challenge hash.
  /// - `z`: A `PolyVec` object representing the polynomial vector `z`.
  /// - `h`: A `PolyVec` object representing the polynomial vector `h`.
  static void packSig(int gamma1, int omega, Uint8List sig, Uint8List c, PolyVec z, PolyVec h) {
    int POLYZ_PACKEDBYTES = getPolyZPackedBytes(gamma1);

    int off = 0;
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) sig[i] = c[i];
    off += Dilithium.SEEDBYTES;

    for (int i = 0; i < z.length; i++) {
      z.poly[i].zpack(gamma1, sig, off);
      off += POLYZ_PACKEDBYTES;
    }

    // Encode h
    for (int i = 0; i < omega + h.length; i++) sig[off + i] = 0;
    int k = 0;
    for (int i = 0; i < h.length; i++) {
      for (int j = 0; j < Dilithium.N; j++) {
        if (h.poly[i].coef[j] != 0) {
          sig[off + k++] = j;
        }
      }

      sig[off + omega + i] = k;
    }
  }

  /// Packs the `w1` components of the polynomial vector into a `Uint8List`.
  /// 
  /// Parameters:
  /// - `gamma2`: The parameter determining the range of coefficients for `w1`.
  /// - `w`: A `PolyVec` object representing the polynomial vector `w`.
  /// - `sig`: A `Uint8List` to store the packed `w1` components.
  static void packw1(int gamma2, PolyVec w, Uint8List sig) {
    int POLYW1_PACKEDBYTES = getPolyW1PackedBytes(gamma2);
    int off = 0;
    for (int i = 0; i < w.length; i++) {
      w.poly[i].w1pack(gamma2, sig, off);
      off += POLYW1_PACKEDBYTES;
    }
  }
  
  /// Unpacks a polynomial from the given `Uint8List` starting at the specified offset.
  /// 
  /// Parameters:
  /// - `gamma1`: The parameter determining the range of coefficients for the polynomial.
  /// - `sig`: A `Uint8List` containing the packed polynomial data.
  /// - `off`: The offset in the `sig` array where the packed data starts.
  /// 
  /// Returns:
  /// - A `Poly` object containing the unpacked coefficients.
  static Poly zunpack(int gamma1, Uint8List sig, int off) {
    Poly pre = Poly(Dilithium.N);

    if (gamma1 == (1 << 17)) {
      for (int i = 0; i < Dilithium.N ~/ 4; i++) {
        pre.coef[4 * i + 0] = sig[off + 9 * i + 0] & 0xFF;
        pre.coef[4 * i + 0] |= (sig[off + 9 * i + 1] & 0xFF) << 8;
        pre.coef[4 * i + 0] |= (sig[off + 9 * i + 2] & 0xFF) << 16;
        pre.coef[4 * i + 0] &= 0x3FFFF;

        pre.coef[4 * i + 1] = (sig[off + 9 * i + 2] & 0xFF) >> 2;
        pre.coef[4 * i + 1] |= (sig[off + 9 * i + 3] & 0xFF) << 6;
        pre.coef[4 * i + 1] |= (sig[off + 9 * i + 4] & 0xFF) << 14;
        pre.coef[4 * i + 1] &= 0x3FFFF;

        pre.coef[4 * i + 2] = (sig[off + 9 * i + 4] & 0xFF) >> 4;
        pre.coef[4 * i + 2] |= (sig[off + 9 * i + 5] & 0xFF) << 4;
        pre.coef[4 * i + 2] |= (sig[off + 9 * i + 6] & 0xFF) << 12;
        pre.coef[4 * i + 2] &= 0x3FFFF;

        pre.coef[4 * i + 3] = (sig[off + 9 * i + 6] & 0xFF) >> 6;
        pre.coef[4 * i + 3] |= (sig[off + 9 * i + 7] & 0xFF) << 2;
        pre.coef[4 * i + 3] |= (sig[off + 9 * i + 8] & 0xFF) << 10;
        pre.coef[4 * i + 3] &= 0x3FFFF;

        pre.coef[4 * i + 0] = gamma1 - pre.coef[4 * i + 0];
        pre.coef[4 * i + 1] = gamma1 - pre.coef[4 * i + 1];
        pre.coef[4 * i + 2] = gamma1 - pre.coef[4 * i + 2];
        pre.coef[4 * i + 3] = gamma1 - pre.coef[4 * i + 3];
      }
    } else if (gamma1 == (1 << 19)) {
      for (int i = 0; i < Dilithium.N ~/ 2; ++i) {
        pre.coef[2 * i + 0] = (sig[off + 5 * i + 0] & 0xFF);
        pre.coef[2 * i + 0] |= (sig[off + 5 * i + 1] & 0xFF) << 8;
        pre.coef[2 * i + 0] |= (sig[off + 5 * i + 2] & 0xFF) << 16;
        pre.coef[2 * i + 0] &= 0xFFFFF;

        pre.coef[2 * i + 1] = (sig[off + 5 * i + 2] & 0xFF) >> 4;
        pre.coef[2 * i + 1] |= (sig[off + 5 * i + 3] & 0xFF) << 4;
        pre.coef[2 * i + 1] |= (sig[off + 5 * i + 4] & 0xFF) << 12;
        pre.coef[2 * i + 1] &= 0xFFFFF;

        pre.coef[2 * i + 0] = gamma1 - pre.coef[2 * i + 0];
        pre.coef[2 * i + 1] = gamma1 - pre.coef[2 * i + 1];
      }
    }

    return pre;
  }
}