import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';


class PackingUtils {

  static Poly etaunpack(int eta, Uint8List bytes, int off) {
    Poly p = Poly(Dilithium.N);
    if (eta == 2) {
      for (int i = 0; i < Dilithium.N ~/ 8; i++) {
        p.coef[8 * i + 0] = (bytes[off + 3 * i + 0] >> 0) & 7;
        p.coef[8 * i + 1] = (bytes[off + 3 * i + 0] >> 3) & 7;
        p.coef[8 * i + 2] = ((bytes[off + 3 * i + 0] >> 6) | (bytes[off + 3 * i + 1] << 2)) & 7;
        p.coef[8 * i + 3] = (bytes[off + 3 * i + 1] >> 1) & 7;
        p.coef[8 * i + 4] = (bytes[off + 3 * i + 1] >> 4) & 7;
        p.coef[8 * i + 5] = ((bytes[off + 3 * i + 1] >> 7) | (bytes[off + 3 * i + 2] << 1)) & 7;
        p.coef[8 * i + 6] = (bytes[off + 3 * i + 2] >> 2) & 7;
        p.coef[8 * i + 7] = (bytes[off + 3 * i + 2] >> 5) & 7;

        p.coef[8 * i + 0] = eta - p.coef[8 * i + 0];
        p.coef[8 * i + 1] = eta - p.coef[8 * i + 1];
        p.coef[8 * i + 2] = eta - p.coef[8 * i + 2];
        p.coef[8 * i + 3] = eta - p.coef[8 * i + 3];
        p.coef[8 * i + 4] = eta - p.coef[8 * i + 4];
        p.coef[8 * i + 5] = eta - p.coef[8 * i + 5];
        p.coef[8 * i + 6] = eta - p.coef[8 * i + 6];
        p.coef[8 * i + 7] = eta - p.coef[8 * i + 7];
      }
    } else if (eta == 4) {
      for (int i = 0; i < Dilithium.N ~/ 2; i++) {
        p.coef[2 * i + 0] = bytes[off + i] & 0x0F;
        p.coef[2 * i + 1] = bytes[off + i] >> 4;
        p.coef[2 * i + 0] = eta - p.coef[2 * i + 0];
        p.coef[2 * i + 1] = eta - p.coef[2 * i + 1];
      }
    } else {
      throw ArgumentError('Unknown eta: $eta');
    }
    return p;
  }

  static int getPolyEtaPackedBytes(int eta) {
    if (eta == 2) {
      return 96;
    } else if (eta == 4) {
      return 128;
    } else {
      throw ArgumentError('Invalid eta: $eta');
    }
  }

  static int getPolyW1PackedBytes(int gamma2) {
    if (gamma2 == (Dilithium.Q - 1) ~/ 88) {
      return 192;
    } else if (gamma2 == (Dilithium.Q - 1) ~/ 32) {
      return 128;
    } else {
      throw ArgumentError('Error invalid gamma2: $gamma2');
    }
  }

  static int getPolyZPackedBytes(int gamma1) {
    if (gamma1 == (1 << 17)) {
      return 576;
    } else if (gamma1 == (1 << 19)) {
      return 640;
    } else {
      throw ArgumentError('Invalid gamma1: $gamma1');
    }
  }

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
        throw ArgumentError('Illegal eta');
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

  static Uint8List packPubKey(Uint8List rho, PolyVec t) {
    int CRYPTO_PUBLICKEYBYTES = Dilithium.SEEDBYTES + t.length * Dilithium.POLYT1_PACKEDBYTES;

    Uint8List pk = Uint8List(CRYPTO_PUBLICKEYBYTES);
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) pk[i] = rho[i];

    for (int i = 0; i < t.length; i++) {
      t.poly[i].t1pack(pk, Dilithium.SEEDBYTES + i * Dilithium.POLYT1_PACKEDBYTES);
    }
    return pk;
  }

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

  static void packw1(int gamma2, PolyVec w, Uint8List sig) {
    int POLYW1_PACKEDBYTES = getPolyW1PackedBytes(gamma2);
    int off = 0;
    for (int i = 0; i < w.length; i++) {
      w.poly[i].w1pack(gamma2, sig, off);
      off += POLYW1_PACKEDBYTES;
    }
  }

  static Poly t0unpack(Uint8List bytes, int off) {
    Poly p = Poly(Dilithium.N);
    for (int i = 0; i < Dilithium.N ~/ 8; i++) {
      p.coef[8 * i + 0] = (bytes[off + 13 * i + 0] & 0xFF);
      p.coef[8 * i + 0] |= (bytes[off + 13 * i + 1] & 0xFF) << 8;
      p.coef[8 * i + 0] &= 0x1FFF;

      p.coef[8 * i + 1] = (bytes[off + 13 * i + 1] & 0xFF) >> 5;
      p.coef[8 * i + 1] |= (bytes[off + 13 * i + 2] & 0xFF) << 3;
      p.coef[8 * i + 1] |= (bytes[off + 13 * i + 3] & 0xFF) << 11;
      p.coef[8 * i + 1] &= 0x1FFF;

      p.coef[8 * i + 2] = (bytes[off + 13 * i + 3] & 0xFF) >> 2;
      p.coef[8 * i + 2] |= (bytes[off + 13 * i + 4] & 0xFF) << 6;
      p.coef[8 * i + 2] &= 0x1FFF;

      p.coef[8 * i + 3] = (bytes[off + 13 * i + 4] & 0xFF) >> 7;
      p.coef[8 * i + 3] |= (bytes[off + 13 * i + 5] & 0xFF) << 1;
      p.coef[8 * i + 3] |= (bytes[off + 13 * i + 6] & 0xFF) << 9;
      p.coef[8 * i + 3] &= 0x1FFF;

      p.coef[8 * i + 4] = (bytes[off + 13 * i + 6] & 0xFF) >> 4;
      p.coef[8 * i + 4] |= (bytes[off + 13 * i + 7] & 0xFF) << 4;
      p.coef[8 * i + 4] |= (bytes[off + 13 * i + 8] & 0xFF) << 12;
      p.coef[8 * i + 4] &= 0x1FFF;

      p.coef[8 * i + 5] = (bytes[off + 13 * i + 8] & 0xFF) >> 1;
      p.coef[8 * i + 5] |= (bytes[off + 13 * i + 9] & 0xFF) << 7;
      p.coef[8 * i + 5] &= 0x1FFF;

      p.coef[8 * i + 6] = (bytes[off + 13 * i + 9] & 0xFF) >> 6;
      p.coef[8 * i + 6] |= (bytes[off + 13 * i + 10] & 0xFF) << 2;
      p.coef[8 * i + 6] |= (bytes[off + 13 * i + 11] & 0xFF) << 10;
      p.coef[8 * i + 6] &= 0x1FFF;

      p.coef[8 * i + 7] = (bytes[off + 13 * i + 11] & 0xFF) >> 3;
      p.coef[8 * i + 7] |= (bytes[off + 13 * i + 12] & 0xFF) << 5;
      p.coef[8 * i + 7] &= 0x1FFF;

      p.coef[8 * i + 0] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 0];
      p.coef[8 * i + 1] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 1];
      p.coef[8 * i + 2] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 2];
      p.coef[8 * i + 3] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 3];
      p.coef[8 * i + 4] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 4];
      p.coef[8 * i + 5] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 5];
      p.coef[8 * i + 6] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 6];
      p.coef[8 * i + 7] = (1 << (Dilithium.D - 1)) - p.coef[8 * i + 7];
    }
    return p;
  }

  static Poly t1unpack(Uint8List bytes, int off) {
    Poly p = Poly(Dilithium.N);
    for (int i = 0; i < Dilithium.N ~/ 4; i++) {
      p.coef[4 * i + 0] = (((bytes[off + 5 * i + 0] & 0xFF) >> 0) | ((bytes[off + 5 * i + 1] & 0xFF) << 8)) & 0x3FF;
      p.coef[4 * i + 1] = (((bytes[off + 5 * i + 1] & 0xFF) >> 2) | ((bytes[off + 5 * i + 2] & 0xFF) << 6)) & 0x3FF;
      p.coef[4 * i + 2] = (((bytes[off + 5 * i + 2] & 0xFF) >> 4) | ((bytes[off + 5 * i + 3] & 0xFF) << 4)) & 0x3FF;
      p.coef[4 * i + 3] = (((bytes[off + 5 * i + 3] & 0xFF) >> 6) | ((bytes[off + 5 * i + 4] & 0xFF) << 2)) & 0x3FF;
    }
    return p;
  }

  static DilithiumPrivateKey unpackPrivateKey(DilithiumParameterSpec parameterSpec, Uint8List bytes) {
    final int POLYETA_PACKEDBYTES = getPolyEtaPackedBytes(parameterSpec.eta);

    int off = 0;
    Uint8List rho = Uint8List(Dilithium.SEEDBYTES);
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) {
      rho[i] = bytes[i];
    }
    off += Dilithium.SEEDBYTES;

    Uint8List key = Uint8List(Dilithium.SEEDBYTES);
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) {
      key[i] = bytes[off + i];
    }
    off += Dilithium.SEEDBYTES;

    Uint8List tr = Uint8List(Dilithium.CRHBYTES);
    for (int i = 0; i < Dilithium.CRHBYTES; i++) {
      tr[i] = bytes[off + i];
    }
    off += Dilithium.CRHBYTES;

    PolyVec s1 = PolyVec(parameterSpec.l);
    for (int i = 0; i < parameterSpec.l; i++) {
      s1.poly[i] = etaunpack(parameterSpec.eta, bytes, off);
      off += POLYETA_PACKEDBYTES;
    }

    PolyVec s2 = PolyVec(parameterSpec.k);
    for (int i = 0; i < parameterSpec.k; i++) {
      s2.poly[i] = etaunpack(parameterSpec.eta, bytes, off);
      off += POLYETA_PACKEDBYTES;
    }

    PolyVec t0 = PolyVec(parameterSpec.k);
    for (int i = 0; i < parameterSpec.k; i++) {
      t0.poly[i] = t0unpack(bytes, off);
      off += Dilithium.POLYT0_PACKEDBYTES;
    }

    // Precompute A, s0, s1 & t0hat
    List<PolyVec> A = Dilithium.expandA(rho, parameterSpec.k, parameterSpec.l);
    PolyVec s1hat = s1.ntt();
    PolyVec s2hat = s2.ntt();
    PolyVec t0hat = t0.ntt();

    return DilithiumPrivateKeyImpl(parameterSpec, rho, key, tr, s1, s2, t0, bytes, A, s1hat, s2hat, t0hat);
  }

  static DilithiumPublicKey unpackPublicKey(DilithiumParameterSpec parameterSpec, Uint8List bytes) {
    int off = 0;
    Uint8List rho = Uint8List(Dilithium.SEEDBYTES);
    for (int i = 0; i < Dilithium.SEEDBYTES; i++) {
      rho[i] = bytes[i];
    }
    off += Dilithium.SEEDBYTES;

    PolyVec p = PolyVec(parameterSpec.k);
    for (int i = 0; i < parameterSpec.k; i++) {
      p.poly[i] = t1unpack(bytes, off);
      off += Dilithium.POLYT1_PACKEDBYTES;
    }

    // Precompute A
    List<PolyVec> A = Dilithium.expandA(rho, parameterSpec.k, parameterSpec.l);
    return DilithiumPublicKeyImpl(parameterSpec, rho, p, bytes, A);
  }

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