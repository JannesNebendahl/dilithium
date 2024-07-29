import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:dilithium/src/impl/dilithium_private_key_impl.dart';
import 'package:dilithium/src/impl/dilithium_public_key_impl.dart';
import 'package:dilithium/src/impl/packing_utils.dart';
import 'package:dilithium/src/impl/poly.dart';
import 'package:dilithium/src/impl/poly_vec.dart';
import 'package:dilithium/src/impl/utils.dart';
import 'package:pointycastle/digests/shake.dart';

class Dilithium {
  static const int N = 256;
  static const int Q = 8380417;
  static const int QINV = 58728449; // q^(-1) mod 2^32
  static const int D = 13;

  static const int POLYT0_PACKEDBYTES = 416;
  static const int POLYT1_PACKEDBYTES = 320;
  static const int SEEDBYTES = 32;
  static const int CRHBYTES = 32;
  static const int SHAKE128_RATE = 168;
  static const int SHAKE256_RATE = 136;
  static const int STREAM128_BLOCKBYTES = SHAKE128_RATE;
  static const int STREAM256_BLOCKBYTES = SHAKE256_RATE;
  static const int POLY_UNIFORM_GAMMA1_NBLOCKS = ((576 + STREAM256_BLOCKBYTES - 1) ~/ STREAM256_BLOCKBYTES);

  static const List<int> zetas = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497,
    2680103, 2725464, 1024112, -1079900, 3585928, -549488, -1119584,
    2619752, -2108549, -2118186, -3859737, -1399561, -3277672,
    1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325,
    3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420,
    3699596, 811944, 531354, 954230, 3881043, 3900724, -2556880,
    2071892, -2797779, -3930395, -1528703, -3677745, -3041255,
    -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598,
    -1000202, -3190144, -3157330, -3632928, 126922, 3412210, -983419,
    2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102,
    -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516,
    3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977,
    759969, -1316856, 189548, -3553272, 3159746, -1851402, -2409325,
    -177440, 1315589, 1341330, 1285669, -1584928, -812732, -1439742,
    -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439,
    -1235728, 3513181, -3520352, -3759364, -1197226, -3193378, 900702,
    1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622,
    -3595838, 342297, 286988, -2437823, 4108315, 3437287, -3342277,
    1735879, 203044, 2842341, 2691481, -2590150, 1265009, 4055324,
    1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272,
    -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210,
    -1430225, -451100, 1312455, 3306115, -1962642, -1279661, 1917081,
    -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136,
    -3776993, -2013608, 2432395, 2454455, -164721, 1957272, 3369112,
    185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760,
    2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090,
    1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154,
    1976782
  ];

  static const int MUBYTES = 64;

  static DilithiumKeyPair generateKeyPair(DilithiumParameterSpec spec, Uint8List seed) {
    Uint8List zeta = seed;

    Uint8List o = Utils.getSHAKE256Digest(2 * 32 + 64, [zeta]);
    Uint8List rho = Uint8List(32);
    Uint8List rhoprime = Uint8List(64);
    Uint8List K = Uint8List(32);

    rho.setRange(0, 32, o.sublist(0, 32));
    rhoprime.setRange(0, 64, o.sublist(32, 96));
    K.setRange(0, 32, o.sublist(96, 128));

    PolyVec s1 = PolyVec.randomVec(rhoprime, spec.eta, spec.l, 0);
    PolyVec s2 = PolyVec.randomVec(rhoprime, spec.eta, spec.k, spec.l);

    // Generate A
    List<PolyVec> A = expandA(rho, spec.k, spec.l);

    PolyVec s1hat = s1.ntt();
    PolyVec t1 = s1hat.mulMatrixPointwiseMontgomery(A);
    t1.reduce();
    t1.invnttTomont();

    t1 = t1.add(s2);
    t1.caddq();

    List<PolyVec> res = t1.powerRound();
    Uint8List pubbytes = PackingUtils.packPubKey(rho, res[1]);

    Uint8List tr = Utils.crh(pubbytes);

    Uint8List prvbytes = PackingUtils.packPrvKey(spec.eta, rho, tr, K, res[0], s1, s2);

    PolyVec s2hat = s2.ntt();
    PolyVec t0hat = res[0].ntt();

    DilithiumPrivateKeyImpl prv = DilithiumPrivateKeyImpl(spec, rho, K, tr, s1, s2, res[0], prvbytes, A, s1hat, s2hat, t0hat);
    DilithiumPublicKeyImpl pub = DilithiumPublicKeyImpl(spec, rho, res[1], pubbytes, A);
    return DilithiumKeyPair(pub, prv);
  }

  static Uint8List sign(DilithiumPrivateKey prv, Uint8List M) {
    var spec = prv.getSpec();
    var CRYPTO_BYTES = Utils.getSigLength(spec);
    var sig = Uint8List(CRYPTO_BYTES);

    List<PolyVec> A;
    if (prv is DilithiumPrivateKeyImpl) {
      A = prv.getA();
    } else {
      A = expandA(prv.getRho(), spec.k, spec.l);
    }

    var conc = Utils.concat([prv.getTr(), M]);
    var mu = Utils.mucrh(conc);
    conc = Utils.concat([prv.getK(), mu]);
    var rhoprime = Utils.mucrh(conc);

    PolyVec s1, s2, t0;
    if (prv is DilithiumPrivateKeyImpl) {
      A = prv.getA();
      s1 = prv.getS1Hat();
      s2 = prv.getS2Hat();
      t0 = prv.getT0Hat();
    } else {
      s1 = prv.getS1().ntt();
      s2 = prv.getS2().ntt();
      t0 = prv.getT0().ntt();
    }

    var kappa = 0;
    for (;;) {
      var y = PolyVec.randomVecGamma1(rhoprime, spec.l, spec.gamma1, kappa++);
      var z = y.ntt();
      var w = z.mulMatrixPointwiseMontgomery(A);
      w.reduce();
      w.invnttTomont();
      w.caddq();
      var res = w.decompose(spec.gamma2);
      PackingUtils.packw1(spec.gamma2, res[1], sig);

      var s = SHAKEDigest(256);
      s.update(mu, 0, mu.length);
      s.update(sig, 0, res[1].length * PackingUtils.getPolyW1PackedBytes(spec.gamma2));
      s.doOutput(sig, 0, SEEDBYTES);

      var cp = generateChallenge(spec.tau, sig);
      cp = cp.ntt();
      z = s1.pointwiseMontgomery(cp);
      z.invnttTomont();
      z = z.add(y);
      z.reduce();
      if (z.chknorm(spec.gamma1 - spec.beta)) {
        continue;
      }
      var h = s2.pointwiseMontgomery(cp);
      h.invnttTomont();
      var w0 = res[0].sub(h);
      w0.reduce();
      if (w0.chknorm(spec.gamma2 - spec.beta)) {
        continue;
      }

      h = t0.pointwiseMontgomery(cp);
      h.invnttTomont();
      h.reduce();
      if (h.chknorm(spec.gamma2)) {
        continue;
      }

      w0 = w0.add(h);
      w0.caddq();

      var hints = makeHints(spec.gamma2, w0, res[1]);
      if (hints.cnt > spec.omega) {
        continue;
      }

      PackingUtils.packSig(spec.gamma1, spec.omega, sig, sig, z, hints.v);
      return sig;
    }
  }

  static bool verify(DilithiumPublicKey pk, Uint8List sig, Uint8List M) {
    var spec = pk.getSpec();
    var CRYPTO_BYTES = Utils.getSigLength(spec);

    if (sig.length != CRYPTO_BYTES) {
      throw Exception("Bad signature");
    }

    var t1 = pk.getT1();

    var off = 0;
    var c = Uint8List(SEEDBYTES);
    c.setAll(0, sig.sublist(0, SEEDBYTES));
    off += SEEDBYTES;

    var z = PolyVec(spec.l);
    for (var i = 0; i < spec.l; i++) {
      z.poly[i] = PackingUtils.zunpack(spec.gamma1, sig, off);
      off += PackingUtils.getPolyZPackedBytes(spec.gamma1);
    }

    var h = PolyVec(spec.k);
    var k = 0;
    for (var i = 0; i < h.length; i++) {
      h.poly[i] = Poly(N);

      if ((sig[off + spec.omega + i] & 0xFF) < k || (sig[off + spec.omega + i] & 0xFF) > spec.omega)
        throw Exception("Bad signature");

      for (var j = k; j < (sig[off + spec.omega + i] & 0xFF); j++) {
        /* Coefficients are ordered for strong unforgeability */
        if (j > k && (sig[off + j] & 0xFF) <= (sig[off + j - 1] & 0xFF))
          throw Exception("Bad signature");
        h.poly[i].coef[sig[off + j] & 0xFF] = 1;
      }

      k = (sig[off + spec.omega + i] & 0xFF);
    }

    for (var j = k; j < spec.omega; j++) {
      if (sig[off + j] != 0) {
        throw InvalidSignature();
      }
    }

    if (z.chknorm(spec.gamma1 - spec.beta)) {
      throw Exception("Bad signature");
    }

    var mu = Utils.crh(pk.getEncoded());
    mu = Utils.getSHAKE256Digest(MUBYTES, [mu, M]);

    var cp = generateChallenge(spec.tau, c);

    List<PolyVec> A;
    if (pk is DilithiumPublicKeyImpl) {
      A = (pk as DilithiumPublicKeyImpl).getA();
    } else {
      A = expandA(pk.getRho(), spec.k, spec.l);
    }
    z = z.ntt();
    var w = z.mulMatrixPointwiseMontgomery(A);

    cp = cp.ntt();
    t1 = t1.shift();
    t1 = t1.ntt();

    t1 = t1.pointwiseMontgomery(cp);
    w = w.sub(t1);
    w.reduce();
    w.invnttTomont();
    w.caddq();

    w = _useHintPolyVec(spec.gamma2, w, h);

    var buf = Uint8List(PackingUtils.getPolyW1PackedBytes(spec.gamma2) * w.length);
    PackingUtils.packw1(spec.gamma2, w, buf);

    var c2 = Utils.getSHAKE256Digest(SEEDBYTES, [mu, buf]);
    for (var i = 0; i < SEEDBYTES; i++) {
      if (c[i] != c2[i]) {
        return false;
      }
    }
    return true;
  }

  static List<PolyVec> expandA(Uint8List rho, int k, int l) {
    List<PolyVec> A = List.generate(k, (_) => PolyVec(l));
    for (int i = 0; i < k; i++) {
      for (int j = 0; j < l; j++) {
        A[i].poly[j] = Poly.genUniformRandom(rho, (i << 8) + j);
      }
    }
    return A;
  }

  static PolyVec _useHintPolyVec(int gamma2, PolyVec u, PolyVec h) {
    PolyVec res = PolyVec(u.length);
    for (int i = 0; i < res.length; i++) {
      res.poly[i] = _useHintPoly(gamma2, u.poly[i], h.poly[i]);
    }
    return res;
  }

  static Poly _useHintPoly(int gamma2, Poly u, Poly h) {
    Poly res = Poly(Dilithium.N);
    for (int i = 0; i < Dilithium.N; i++) {
      res.coef[i] = _useHintInt(gamma2, u.coef[i], h.coef[i]);
    }
    return res;
  }

  static int _useHintInt(int gamma2, int a, int hint) {
    int a0, a1;

    a1 = (a + 127) >> 7;
    if (gamma2 == (Dilithium.Q - 1) / 32) {
      a1 = (a1 * 1025 + (1 << 21)) >> 22;
      a1 &= 15;
    } else if (gamma2 == (Dilithium.Q - 1) / 88) {
      a1 = (a1 * 11275 + (1 << 23)) >> 24;
      a1 ^= ((43 - a1) >> 31) & a1;
    } else {
      throw Exception("Invalid gamma2: $gamma2");
    }
    a0 = a - a1 * 2 * gamma2;
    a0 -= (((Dilithium.Q - 1) ~/ 2 - a0) >> 31) & Dilithium.Q;

    if (hint == 0) {
      return a1;
    }

    if (gamma2 == (Dilithium.Q - 1) / 32) {
      if (a0 > 0)
        return (a1 + 1) & 15;
      else
        return (a1 - 1) & 15;
    } else if (gamma2 == (Dilithium.Q - 1) / 88) {
      if (a0 > 0)
        return (a1 == 43) ? 0 : a1 + 1;
      else
        return (a1 == 0) ? 43 : a1 - 1;
    } else {
      throw Exception("Invalid gamma2: $gamma2");
    }
  }

  static _Hints makeHints(int gamma2, PolyVec v0, PolyVec v1) {
    PolyVec hintsVec = PolyVec(v0.length);
    int hintsCnt = 0;

    for (int i = 0; i < v0.length; i++) {
      _Hint hint = polyMakeHint(gamma2, v0.poly[i], v1.poly[i]);
      hintsCnt += hint.cnt;
      hintsVec.poly[i] = hint.v;
    }
    return _Hints(hintsVec, hintsCnt);
  }

  static _Hint polyMakeHint(int gamma2, Poly a, Poly b) {
    Poly hintPoly = Poly(N);
    int hintCnt = 0;

    for (int i = 0; i < N; i++) {
      hintPoly.coef[i] = _makeHint(gamma2, a.coef[i], b.coef[i]);
      hintCnt += hintPoly.coef[i];
    }
    return _Hint(hintPoly, hintCnt);
  }

  static int _makeHint(int gamma2, int a0, int a1) {
    if (a0 <= gamma2 || a0 > Q - gamma2 || (a0 == Q - gamma2 && a1 == 0)) {
      return 0;
    }
    return 1;
  }

  static Poly generateChallenge(int tau, Uint8List seed) {
    Poly pre = Poly(Dilithium.N);
    int b, pos;
    int signs;
    Uint8List buf = Uint8List(Dilithium.SHAKE256_RATE);

    final s = SHAKEDigest(256);
    s.update(seed, 0, Dilithium.SEEDBYTES);
    s.doOutput(buf, 0, buf.length);

    signs = 0;
    for (int i = 0; i < 8; i++) signs |= (buf[i] & 0xFF) << (8 * i);
    pos = 8;

    for (int i = Dilithium.N - tau; i < Dilithium.N; ++i) {
      do {
        if (pos >= Dilithium.SHAKE256_RATE) {
          s.doOutput(buf, 0, buf.length);
          pos = 0;
        }
        b = (buf[pos++] & 0xFF);
      } while (b > i);
      pre.coef[i] = pre.coef[b];
      pre.coef[b] = 1 - 2 * (signs & 1);
      signs >>= 1;
    }
    return pre;
  }
}

class _Hints {
  final PolyVec v;
  final int cnt;

  _Hints(this.v, this.cnt);
}

class _Hint {
  final Poly v;
  final int cnt;

  _Hint(this.v, this.cnt);
}

  