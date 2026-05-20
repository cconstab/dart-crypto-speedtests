import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as openssl;

Uint8List aes(Uint8List input, Uint8List key, Uint8List iv, {required bool encrypt}) {
  if (key.length != 32) {
    throw ArgumentError.value(key.length, 'key', 'Key must be 32 bytes for AES-256-CBC');
  }
  if (iv.length != 16) {
    throw ArgumentError.value(iv.length, 'iv', 'IV must be 16 bytes for AES-256-CBC');
  }

  return using((arena) {
    final ctx = openssl.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw StateError('Failed to create EVP_CIPHER_CTX');

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
    if (initResult != 1) throw StateError('OpenSSL AES init step failed: $initResult');

    final updateResult = encrypt
        ? openssl.EVP_EncryptUpdate(ctx, outPtr.cast(), outLenPtr, inPtr.cast(), input.length)
        : openssl.EVP_DecryptUpdate(ctx, outPtr.cast(), outLenPtr, inPtr.cast(), input.length);
    if (updateResult != 1) throw StateError('OpenSSL AES update step failed: $updateResult');

    var outLen = outLenPtr.value;
    final finalResult = encrypt
        ? openssl.EVP_EncryptFinal_ex(ctx, outPtr.elementAt(outLen).cast(), outLenPtr)
        : openssl.EVP_DecryptFinal_ex(ctx, outPtr.elementAt(outLen).cast(), outLenPtr);
    if (finalResult != 1) throw StateError('OpenSSL AES final step failed: $finalResult');

    outLen += outLenPtr.value;
    return Uint8List.fromList(outPtr.asTypedList(outLen));
  });
}

void main() {
  final key = utf8.encode('Nc92PMoPjcIls5QoXeki5yIPuhjjWMcx');
  final iv = utf8.encode('1234567890123456');
  final plaintext = utf8.encode('Secret message for AES-256-CBC');

  final encrypted = aes(Uint8List.fromList(plaintext), Uint8List.fromList(key), Uint8List.fromList(iv), encrypt: true);
  final decrypted = aes(encrypted, Uint8List.fromList(key), Uint8List.fromList(iv), encrypt: false);

  print('cipher (base64): ${base64.encode(encrypted)}');
  print('roundtrip text: ${utf8.decode(decrypted)}');
}
