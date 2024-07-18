import 'dart:typed_data';

import 'package:dilithium/dilithium.dart';
import 'package:pointycastle/digests/shake.dart';

class Utils {
  static void clear(Uint8List x) {
    for (int i = 0; i < x.length; i++) {
      x[i] = 0;
    }
  }

  static Uint8List concat(List<Uint8List> arr) {
    int totalLength = arr.fold(0, (sum, x) => sum + x.length);
    Uint8List result = Uint8List(totalLength);
    int offset = 0;
    for (Uint8List x in arr) {
      result.setRange(offset, offset + x.length, x);
      offset += x.length;
    }
    return result;
  }

  static Uint8List getSHAKE256Digest(int sz, List<Uint8List> arr) {
    Uint8List c = concat(arr);
    var s = SHAKEDigest(256);
    s.update(c, 0, c.length);
    Uint8List o = Uint8List(sz);
    s.doOutput(o, 0, o.length);
    return o;
  }

  static Uint8List crh(Uint8List p) {
    return getSHAKE256Digest(Dilithium.CRHBYTES, [p]);
  }

  static Uint8List mucrh(Uint8List p) {
    return getSHAKE256Digest(Dilithium.MUBYTES, [p]);
  }

  static int getSigLength(DilithiumParameterSpec spec) {
    return (Dilithium.SEEDBYTES + spec.l * PackingUtils.getPolyZPackedBytes(spec.gamma1) + spec.omega + spec.k).toInt();
  }
}