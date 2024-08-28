[![Tests](https://github.com/JannesNebendahl/dilithium/actions/workflows/tests.yml/badge.svg)](https://github.com/JannesNebendahl/dilithium/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/JannesNebendahl/dilithium/graph/badge.svg?token=22U0DA66BD)](https://codecov.io/github/JannesNebendahl/dilithium)  
Dart implementation of the [Dilithium](https://www.pq-crystals.org/dilithium/) signature scheme, which supports all 3 security levels (2, 3, 5)

**Note AES Not Supported:** This Dart implementation of Dilithium does not support the AES variant. It only supports the SHAKE-based version of the algorithm.

## Usage

### Key Pair Generation:
```dart
Uint8List randomSeed = Uint8List(Dilithium.SEEDBYTES);

DilithiumKeyPair keyPair = Dilithium.generateKeyPair(DilithiumParameterSpec.LEVEL3, randomSeed);

DilithiumPublicKey sk = keyPair.publicKey;
DilithiumPrivateKey pk = keyPair.privateKey;
```
Note that you must provide an algorithm's parameter spec representing the desired security level - the above example uses level 3, but you can select 2 and 5 as well. The three parameter spec objects are declared as static fields on the DilithiumParameterSpec class. Alternatively, a static method, getSpecForSecurityLevel(), is provided on DilithiumParameterSpec, allowing you to easily retrieve the spec for a given level at runtime.

### Signing:
Having generated a key pair, use the private key of it to sign a message, which has to be encoded as an Uint8List. (More to encoding messages as Uint8Lists under )
```dart
Uint8List message = utf8.encode("Valid Message");

Uint8List signature = Dilithium.sign(keyPair.privateKey, message);
```

### Signature verification
```dart
bool isValid = Dilithium.verify(keyPair.publicKey, signature, message);
```
The isValid variable indicates whether the message and signature can be verified and have not been modified. Note that a `InvalidSignature` exception can be thrown in case of malformed signatures.

### Keys serialization/deserialization:
You can use the `.serialize()` method of the public and private key to obtain a byte representation of the key (in case of dart this refers to a Uint8List). The formats are compatible with the [c reference implementation](https://github.com/pq-crystals/dilithium) and [java implementation](https://github.com/mthiim/dilithium-java).  
In order to instantiate the keys from a byte representation, the `.deserialize(spec, bytes)` factory is provided. Note that the parameter spec (same as used for generation) needs to be provided and is not encoded in the byte representation neither should be inferred from the number of bytes. Of course, the serialization format could change as well as the standardization process moves along.
```dart
Uint8List encodedPublicKey = keyPair.publicKey.serialize();
Uint8List encodedPrivateKey = keyPair.privateKey.serialize();

final reinstantiatedPk = DilithiumPublicKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPublicKey);
final reinstantiatedSk = DilithiumPrivateKey.deserialize(DilithiumParameterSpec.LEVEL3, encodedPrivateKey);
```

The usage of the package can be further explored in [this](./integration_test/package_usage_test.dart) test.

### Encoding messages as Uint8List
This package is set up to sign and verify messages which are encoded as Uint8List (means practically Byte Streams). Dart provides a variety of options to convert different types to a Uint8List.   
The following code snippets show you conversions of the most typical message types:  

#### String Messages 
```Dart
String stringMsg = 'Hello World!';
Uint8List byteMsg = utf8.encode(stringMsg); // [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]
```

#### Integer Messages
```Dart
int intMsg = 1234567890;

ByteData byteData = ByteData(8); // 8 bytes for int (int64)
byteData.setInt64(0, intMsg);

Uint8List byteMsg = byteData.buffer.asUint8List(); // [0, 0, 0, 0, 73, 150, 2, 210]
```

#### Floating Point Messages
```Dart
double doubleMsg = 3.141592653589793;

ByteData byteData = ByteData(8); // 8 bytes for double
byteData.setFloat64(0, doubleMsg);

Uint8List byteMsg = byteData.buffer.asUint8List(); // [64, 9, 33, 251, 84, 68, 45, 24]
```
You can further investigate the message encoding in [this](./integration_test/msg_setup_test.dart) test.

### Sign-and-Hash-Paradigm
To make the signing and verifying of messages of arbitrary length more efficient, you can use the `Hash-and-Sign-Paradigm`. This approach involves converting the message to a hash and then signing and verifying this hash rather than the entire message. Here's how it works:

Sender:
1. **Hashing the Message**: First, the message or file that needs to be signed is processed through a cryptographic hash function. This function creates a unique, fixed-length hash value (or digital fingerprint) from the original message. Regardless of the size of the original message, the hash value always has the same length, making it efficient to handle.

2. **Signing the Hash**: The generated hash value is then used in the signing process. Using Dilithium, you sign the hash value instead of the original message: `Dilithium.sign(privateKey, hash_value)`. The resulting digital signature, along with the original message, is then sent to the recipient.

Receiver:  
1. **Hashing the Received Message**: Upon receiving the message, the recipient applies the same cryptographic hash function to the received message. This step produces a hash value of the received message. If the communication has not been tampered, this hash value will match the hash value that was signed by the sender.

2. **Verifying the Hash**: To verify the message, the recipient uses Dilithium to check the validity of the signature: `Dilithium.verify(publicKey, hash_value)`. The sender's public key and the newly computed hash value are used in this verification process. If the signature is valid for the hash value, it confirms that the message has not been altered. Any modification in the message would result in a different hash value, which would not match the original signature, thereby indicating tampering.

This method ensures both the integrity and authenticity of the message with arbitrary length while optimizing the efficiency of the signing and verification process.

#### Example: Sign-and-Hash with SHA-256
```Dart
String msg = "This is a long test message, longer than 32 bytes.";

// Sender:
Uint8List originalMsg = utf8.encode(msg);
Uint8List hashValue = Uint8List.fromList(sha256.convert(originalMsg).bytes);

final signature = Dilithium.sign(keyPair.privateKey, hashValue);

// Receiver
String receivedMsg = msg;
Uint8List receivedMsgBytes = utf8.encode(receivedMsg);
Uint8List generatedHashValue = Uint8List.fromList(sha256.convert(receivedMsgBytes).bytes);

bool isValid = Dilithium.verify(keyPair.publicKey, signature, generatedHashValue);
expect(isValid, isTrue); // --> the received message is unmodified
```
This example requires the [crypto](https://pub.dev/packages/crypto) package for SHA-256 hashing. You can further investigate this process in [this](./integration_test/hash_and_sign_test.dart) test.

## What is Dilithium
Dilithium is a post-quantum secure digital signature algorithm designed to provide robust security against potential future quantum computer attacks. It is part of the [CRYSTALS](https://pq-crystals.org/) (Cryptographic Suite for Algebraic Lattices) suite, which is a collection of cryptographic primitives intended to resist quantum computing threats.

Dilithium's key features include:
- Post-Quantum Security: Resistant to attacks from both classical and quantum computers.
- Efficiency: Designed to be efficient in terms of speed and size, making it practical for real-world applications.
- Multiple Security Levels: Supports three security levels (2, 3, and 5), allowing users to choose the appropriate level of security for their needs.

For more detailed information, you can visit the official [Dilithium](https://www.pq-crystals.org/dilithium/) website.

## Advantages of the Dart Implementation

Implementing the Dilithium signature scheme directly in Dart offers several advantages over using the [c reference implementation](https://github.com/pq-crystals/dilithium) via [`dart:ffi`](https://pub.dev/packages/ffi):

1. **Easier integration**: Direct implementation in Dart avoids the complexity of integrating C code using `dart:ffi`. This reduces the need to deal with the details of memory management and the peculiarities of the C API.
2. **Platform independence**: Dart code can be executed on different platforms (iOS, Android, web, desktop) without any changes. When using `dart:ffi`, it must be ensured that the C libraries are available and compatible for each target platform.
3. **Debugging**: Debugging pure Dart code is easier and more convenient than debugging mixed Dart and C code. Dart development environments provide comprehensive debugging tools that make debugging easier.

These advantages make direct implementation in Dart an attractive alternative to using C implementation via `dart:ffi`.

## DISCLAIMER
This package is available under the Apache 2.0 license (see LICENSE). Note that the code has not been examined by a third party for potential vulnerabilities and as mentioned was not made to be used for production use. No warranty of any kind is provided. If you don't like those terms, you must refrain from using this software.

## Credits
This dart implementation is based on the [c reference implementation](https://github.com/pq-crystals/dilithium) and [java implementation](https://github.com/mthiim/dilithium-java). Special thanks to the developers of these projects for their foundational work.
