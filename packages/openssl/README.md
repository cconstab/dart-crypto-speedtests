> Minimum Dart SDK 3.10 (Flutter 3.38) with Native Assets/hooks support.

[![pub.dev](https://img.shields.io/pub/v/openssl.svg)](https://pub.dev/packages/openssl)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

This package builds OpenSSL from source and exposes its full C surface directly to Dart via FFI. There are no Dart-side abstractions: call the OpenSSL APIs as you would in C, manage memory manually, and follow the official OpenSSL documentation for usage and lifetime rules.

If you want background on how this package is built with hooks/native assets, see the article: [Dart build hooks: create Dart packages from C libs](https://medium.com/@lucazzp/dart-build-hooks-create-dart-packages-from-c-libs-10cbb9360a69).

## What you get

- Full OpenSSL C API available in Dart (headers mirrored into FFI bindings).
- Native assets build step that compiles OpenSSL locally the first time you run the app.
- No opinionated wrappers; you stay in control of allocation and cleanup.

## Getting started

1) Add the package: `dart pub add openssl` (or add it to your `pubspec.yaml`).
2) Run your app once to trigger the native build (about 1 minute on first run).

## Using the bindings

Import and call OpenSSL functions directly; the generated bindings live under `lib/src/third_party/openssl.g.dart`.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as openssl;

Uint8List aes(Uint8List input, Uint8List key, Uint8List iv, {required bool encrypt}) {
  return using((arena) {
    final ctx = openssl.EVP_CIPHER_CTX_new();
    final inPtr = arena.allocate<Uint8>(input.isEmpty ? 1 : input.length);
    final keyPtr = arena.allocate<Uint8>(key.length);
    final ivPtr = arena.allocate<Uint8>(iv.length);
    final outPtr = arena.allocate<Uint8>(input.length + openssl.EVP_MAX_BLOCK_LENGTH);
    final outLenPtr = arena.allocate<Int>(2);

    inPtr.asTypedList(input.length).setAll(0, input);
    keyPtr.asTypedList(key.length).setAll(0, key);
    ivPtr.asTypedList(iv.length).setAll(0, iv);

    final initResult = encrypt
        ? openssl.EVP_EncryptInit_ex(ctx, openssl.EVP_aes_256_cbc(), nullptr, keyPtr.cast(), ivPtr.cast())
        : openssl.EVP_DecryptInit_ex(ctx, openssl.EVP_aes_256_cbc(), nullptr, keyPtr.cast(), ivPtr.cast());
    if (initResult != 1) throw StateError('init failed');

    final updateResult = encrypt
        ? openssl.EVP_EncryptUpdate(ctx, outPtr.cast(), outLenPtr, inPtr.cast(), input.length)
        : openssl.EVP_DecryptUpdate(ctx, outPtr.cast(), outLenPtr, inPtr.cast(), input.length);
    if (updateResult != 1) throw StateError('update failed');

    var outLen = outLenPtr.value;
    final finalResult = encrypt
        ? openssl.EVP_EncryptFinal_ex(ctx, outPtr.elementAt(outLen).cast(), outLenPtr)
        : openssl.EVP_DecryptFinal_ex(ctx, outPtr.elementAt(outLen).cast(), outLenPtr);
    if (finalResult != 1) throw StateError('final failed');

    outLen += outLenPtr.value;
    return Uint8List.fromList(outPtr.asTypedList(outLen));
  });
}

void main() {
  final key = utf8.encode('Nc92PMoPjcIls5QoXeki5yIPuhjjWMcx');
  final iv = utf8.encode('1234567890123456');
  final plaintext = utf8.encode('Secret message for AES-256-CBC');

  final encrypted = aes(plaintext, Uint8List.fromList(key), Uint8List.fromList(iv), encrypt: true);
  final decrypted = aes(encrypted, Uint8List.fromList(key), Uint8List.fromList(iv), encrypt: false);

  print('cipher (b64): ${base64.encode(encrypted)}');
  print('roundtrip: ${utf8.decode(decrypted)}');
}
```

Remember: follow OpenSSL docs for allocation/free patterns (`OPENSSL_free`, `EVP_*` lifecycle, etc.).

## Build notes and roadmap

- First build compiles OpenSSL; subsequent runs are faster. The goal is to ship precompiled binaries later to skip this step.
- Native assets require Flutter 3.38+/Dart 3.10+ to run the hook pipeline.

## Contributing

For local builds, regenerating bindings, and working with the OpenSSL submodule, see `contrib.md`.
