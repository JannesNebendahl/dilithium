[![Tests](https://github.com/JannesNebendahl/dilithium/actions/workflows/tests.yml/badge.svg)](https://github.com/JannesNebendahl/dilithium/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/JannesNebendahl/dilithium/graph/badge.svg?token=22U0DA66BD)](https://codecov.io/github/JannesNebendahl/dilithium)  
Dart implementation of the [Dilithium](https://www.pq-crystals.org/dilithium/) signature scheme, which supports all 3 security levels (2, 3, 5)

**Note AES Not Supported:** This Dart implementation of Dilithium does not support the AES variant. It only supports the SHAKE-based version of the algorithm.

## Usage

### Key Pair generation:
```dart
Uint8List randomSeed = Uint8List(Dilithium.SEEDBYTES);

DilithiumKeyPair keyPair = Dilithium.generateKeyPair(DilithiumParameterSpec.LEVEL3, randomSeed);

DilithiumPublicKey sk = keyPair.publicKey;
DilithiumPrivateKey pk = keyPair.privateKey;
```
Note that you must provide an algorithm parameter spec representing the desired security level - the above example uses level 3, but you can select 2 and 5 as well. The three parameter spec objects are declared as static fields on the DilithiumParameterSpec class. Alternatively, a static method, getSpecForSecurityLevel(), is provided on DilithiumParameterSpec, allowing you to easily retrieve the spec for a given level at runtime.

### Signing:
Having generated a key pair, use the private key of it to sign a message, which has to be encoded as an Uint8List.
```dart
Uint8List message = utf8.encode("Valid Message");

Uint8List signature = Dilithium.sign(keyPair.privateKey, message);
```

### Signature verification
```dart
bool isValid = Dilithium.verify(keyPair.publicKey, signature, message);
```
The isValid variable shows now if the message and signature can be verified and aren't modified. Note that a `InvalidSignature` exception can be thrown in case of malformed signatures.

### Keys serialization/deserialization:
You can use the `.serialize()` method of the public and private key to obtain a byte representation of the key (in case of dart this refers to a Uint8List). The formats are compatible with the [c reference implementation](https://github.com/pq-crystals/dilithium) and [java implementation](https://github.com/mthiim/dilithium-java).  
In order to instantiate the keys from a byte representation, the `.deserialize(spec, bytes)` factory is provided. Note that the parameter spec (same as used for generation) needs to be provided and is not encoded in the byte representation neither should be inferred from the number of bytes. Of course, the serialization format could change as well as the standardization process moves along.
```dart
Uint8List encodedPublicKey = keyPair.publicKey.serialize();
Uint8List encodedPrivateKey = keyPair.privateKey.serialize();

final reinstantiatedPk = DilithiumPublicKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPublicKey);
final reinstantiatedSk = DilithiumPrivateKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPrivateKey);
```

## What is Dilithium
Dilithium is a post-quantum secure digital signature algorithm designed to provide robust security against potential future quantum computer attacks. It is part of the [CRYSTALS](https://pq-crystals.org/) (Cryptographic Suite for Algebraic Lattices) suite, which is a collection of cryptographic primitives intended to resist quantum computing threats.

Dilithium's key features include:
- Post-Quantum Security: Resistant to attacks from both classical and quantum computers.
- Efficiency: Designed to be efficient in terms of speed and size, making it practical for real-world applications.
- Multiple Security Levels: Supports three security levels (2, 3, and 5), allowing users to choose the appropriate level of security for their needs.

For more detailed information, you can visit the official [Dilithium](https://www.pq-crystals.org/dilithium/) website.

## Advantages of Dart implementation

Implementing the Dilithium signature scheme directly in Dart offers several advantages over using the [c reference implementation](https://github.com/pq-crystals/dilithium) via [`dart:ffi`](https://pub.dev/packages/ffi):

1. **Easier integration**: Direct implementation in Dart avoids the complexity of integrating C code using `dart:ffi`. This reduces the need to deal with the details of memory management and the peculiarities of the C API.
2. **Platform independence**: Dart code can be executed on different platforms (iOS, Android, web, desktop) without any changes. When using `dart:ffi`, it must be ensured that the C libraries are available and compatible for each target platform.
3. **Debugging**: Debugging pure Dart code is easier and more convenient than debugging mixed Dart and C code. Dart development environments provide comprehensive debugging tools that make debugging easier.

These advantages make direct implementation in Dart an attractive alternative to using C implementation via `dart:ffi`.

## DISCLAIMER
This package is available under the Apache 2.0 license (see LICENSE). Note that the code has not been examined by a third party for potential vulnerabilities and as mentioned was not made to be used for production use. No warranty of any kind is provided. If you don't like those terms, you must refrain from using this software.

## Credits
This dart implementation is based on the [c reference implementation](https://github.com/pq-crystals/dilithium) and [java implementation](https://github.com/mthiim/dilithium-java). Special thanks to the developers of these projects for their foundational work.
