import 'dart:typed_data';

import 'package:dilithium_crypto/dilithium_crypto.dart';
import 'package:dilithium_crypto/src/packing_utils.dart';
import 'package:pointycastle/digests/shake.dart';

class Utils {
  /// Concatenates a list of `Uint8List` objects into a single `Uint8List`.
  ///
  /// Parameters:
  /// - `arr`: The list of `Uint8List` objects to concatenate.
  ///
  /// Returns:
  /// - A single `Uint8List` object containing the concatenated data.
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

  /// Generates a SHAKE256 digest of the specified size using the given data.
  ///
  /// Parameters:
  /// - `sz`: The size of the digest to generate.
  /// - `arr`: The list of `Uint8List` objects to use as input data.
  ///
  /// Returns:
  /// - A `Uint8List` object containing the generated digest.
  static Uint8List getSHAKE256Digest(int sz, List<Uint8List> arr) {
    Uint8List c = concat(arr);
    var s = SHAKEDigest(256);
    s.update(c, 0, c.length);
    Uint8List o = Uint8List(sz);
    s.doOutput(o, 0, o.length);
    return o;
  }

  /// Generates a collision-resistant hash (CRH) of the given data.
  ///
  /// Parameters:
  /// - `p`: The data to hash.
  ///
  /// Returns:
  /// - A `Uint8List` object containing the generated CRH.
  static Uint8List crh(Uint8List p) {
    return getSHAKE256Digest(Dilithium.CRHBYTES, [p]);
  }

  /// Generates a message-uniform collision-resistant hash (MUCRH) of the given data.
  ///
  /// Parameters:
  /// - `p`: The data to hash.
  ///
  /// Returns:
  /// - A `Uint8List` object containing the generated MUCRH.
  static Uint8List mucrh(Uint8List p) {
    return getSHAKE256Digest(Dilithium.MUBYTES, [p]);
  }

  /// Returns the length of a signature for the specified parameter spec.
  static int getSigLength(DilithiumParameterSpec spec) {
    return (Dilithium.SEEDBYTES +
            spec.l * PackingUtils.getPolyZPackedBytes(spec.gamma1) +
            spec.omega +
            spec.k)
        .toInt();
  }
}
