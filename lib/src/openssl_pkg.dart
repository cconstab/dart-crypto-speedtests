/// OpenSSL via the `openssl` pub package (pub.dev/packages/openssl).
///
/// The package provides auto-generated FFI bindings compiled at build time
/// via Dart Native Assets / build hooks. OpenSSL is bundled from source —
/// no runtime library path resolution is needed, unlike [OpenSslCrypto].
///
/// Two patterns are provided so their overhead can be compared directly:
///
/// ## Naive — Arena per call (package example style)
///
/// Every call to [opensslPkgSha256], [opensslPkgAes256CtrEncrypt], etc.
/// allocates a fresh [Arena], copies input data into it, runs the crypto,
/// copies output out, then frees everything. This is idiomatic for one-shot
/// use but the 1 MB malloc + memcpy dominates benchmark timing.
///
/// ## Optimised — [OpenSslPkgCrypto] (persistent contexts)
///
/// Same API as [OpenSslCrypto] but backed by the package's bindings instead
/// of our hand-crafted [DynamicLibrary.open] lookups. Persistent EVP contexts
/// and I/O buffers mean zero heap allocation in the hot path. At identical
/// settings the two should produce the same throughput numbers because they
/// call the exact same underlying C symbols.

library;

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:openssl/openssl.dart' as ssl;

// ---------------------------------------------------------------------------
// Naive (Arena-per-call) helpers
// ---------------------------------------------------------------------------

/// SHA-256 via the openssl package, allocating a fresh Arena per call.
Uint8List opensslPkgSha256(Uint8List data) {
  return using((arena) {
    final ctx = ssl.EVP_MD_CTX_new();
    if (ctx == nullptr) throw StateError('EVP_MD_CTX_new failed');
    try {
      final inPtr     = arena.allocate<Uint8>(data.isEmpty ? 1 : data.length);
      final digestPtr = arena.allocate<Uint8>(32);
      final lenPtr    = arena.allocate<Uint32>(1);
      inPtr.asTypedList(data.length).setRange(0, data.length, data);
      ssl.EVP_DigestInit_ex(ctx, ssl.EVP_sha256(), nullptr);
      ssl.EVP_DigestUpdate(ctx, inPtr.cast(), data.length);
      ssl.EVP_DigestFinal_ex(ctx, digestPtr.cast(), lenPtr.cast());
      return Uint8List.fromList(digestPtr.asTypedList(32));
    } finally {
      ssl.EVP_MD_CTX_free(ctx);
    }
  });
}

/// AES-256-CTR encrypt via the openssl package, Arena per call.
Uint8List opensslPkgAes256CtrEncrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
    _pkgCipher(ssl.EVP_aes_256_ctr(), plaintext, key, iv, encrypt: true);

/// AES-256-CTR decrypt via the openssl package, Arena per call.
Uint8List opensslPkgAes256CtrDecrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
    _pkgCipher(ssl.EVP_aes_256_ctr(), ciphertext, key, iv, encrypt: false);

/// ChaCha20 encrypt via the openssl package, Arena per call.
Uint8List opensslPkgChacha20Encrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
    _pkgCipher(ssl.EVP_chacha20(), plaintext, key, iv, encrypt: true);

/// ChaCha20 decrypt via the openssl package, Arena per call.
Uint8List opensslPkgChacha20Decrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
    _pkgCipher(ssl.EVP_chacha20(), ciphertext, key, iv, encrypt: false);

Uint8List _pkgCipher(
  Pointer<ssl.evp_cipher_st> cipher,
  Uint8List input,
  Uint8List key,
  Uint8List iv, {
  required bool encrypt,
}) {
  return using((arena) {
    final ctx = ssl.EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');
    try {
      final inPtr  = arena.allocate<Uint8>(input.isEmpty ? 1 : input.length);
      final keyPtr = arena.allocate<Uint8>(key.length);
      final ivPtr  = arena.allocate<Uint8>(iv.length);
      final outPtr = arena.allocate<Uint8>(input.length + ssl.EVP_MAX_BLOCK_LENGTH);
      final len1   = arena.allocate<Int32>(1);
      final len2   = arena.allocate<Int32>(1);

      inPtr.asTypedList(input.length).setRange(0, input.length, input);
      keyPtr.asTypedList(key.length).setRange(0, key.length, key);
      ivPtr.asTypedList(iv.length).setRange(0, iv.length, iv);

      if (encrypt) {
        ssl.EVP_EncryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast());
        ssl.EVP_EncryptUpdate(ctx, outPtr.cast(), len1.cast(), inPtr.cast(), input.length);
        ssl.EVP_EncryptFinal_ex(ctx, (outPtr + len1.value).cast(), len2.cast());
      } else {
        ssl.EVP_DecryptInit_ex(ctx, cipher, nullptr, keyPtr.cast(), ivPtr.cast());
        ssl.EVP_DecryptUpdate(ctx, outPtr.cast(), len1.cast(), inPtr.cast(), input.length);
        ssl.EVP_DecryptFinal_ex(ctx, (outPtr + len1.value).cast(), len2.cast());
      }
      return Uint8List.fromList(outPtr.asTypedList(len1.value + len2.value));
    } finally {
      ssl.EVP_CIPHER_CTX_free(ctx);
    }
  });
}

// ---------------------------------------------------------------------------
// Optimised — persistent contexts (mirrors OpenSslCrypto)
// ---------------------------------------------------------------------------

/// Wraps the openssl package bindings with the same persistent-context
/// strategy as [OpenSslCrypto]. All EVP contexts and I/O buffers are
/// allocated once; the hot path contains zero heap operations.
class OpenSslPkgCrypto {
  late final Pointer<ssl.evp_md_ctx_st>     _mdCtx;
  late final Pointer<ssl.evp_cipher_ctx_st> _cipherCtx;

  late final Pointer<Uint8>  _digestBuf;
  late final Pointer<Uint32> _digestLen;
  late final Pointer<Int32>  _outLen1;
  late final Pointer<Int32>  _outLen2;
  late final Pointer<Uint8>  _keyBuf;
  late final Pointer<Uint8>  _ivBuf;

  Pointer<Uint8> _inBuf  = nullptr;
  Pointer<Uint8> _outBuf = nullptr;
  int _allocSize = 0;

  void _ensureBufs(int size) {
    if (size <= _allocSize) return;
    if (_allocSize > 0) {
      malloc.free(_inBuf);
      malloc.free(_outBuf);
    }
    _inBuf     = malloc.allocate<Uint8>(size);
    _outBuf    = malloc.allocate<Uint8>(size + 64);
    _allocSize = size;
  }

  OpenSslPkgCrypto() {
    _mdCtx     = ssl.EVP_MD_CTX_new();
    _cipherCtx = ssl.EVP_CIPHER_CTX_new();
    if (_mdCtx == nullptr || _cipherCtx == nullptr) {
      throw StateError('OpenSSL pkg context creation failed');
    }
    _digestBuf = malloc.allocate<Uint8>(32);
    _digestLen = malloc.allocate<Uint32>(1);
    _outLen1   = malloc.allocate<Int32>(1);
    _outLen2   = malloc.allocate<Int32>(1);
    _keyBuf    = malloc.allocate<Uint8>(64);
    _ivBuf     = malloc.allocate<Uint8>(32);
  }

  Uint8List sha256(Uint8List data) {
    _ensureBufs(data.length);
    _inBuf.asTypedList(data.length).setRange(0, data.length, data);
    ssl.EVP_DigestInit_ex(_mdCtx, ssl.EVP_sha256(), nullptr);
    ssl.EVP_DigestUpdate(_mdCtx, _inBuf.cast(), data.length);
    ssl.EVP_DigestFinal_ex(_mdCtx, _digestBuf.cast(), _digestLen.cast());
    return Uint8List.fromList(_digestBuf.asTypedList(32));
  }

  Uint8List aes256CtrEncrypt(Uint8List p, Uint8List key, Uint8List iv) =>
      _cipher(ssl.EVP_aes_256_ctr(), p, key, iv, encrypt: true);

  Uint8List aes256CtrDecrypt(Uint8List c, Uint8List key, Uint8List iv) =>
      _cipher(ssl.EVP_aes_256_ctr(), c, key, iv, encrypt: false);

  Uint8List chacha20Encrypt(Uint8List p, Uint8List key, Uint8List iv) =>
      _cipher(ssl.EVP_chacha20(), p, key, iv, encrypt: true);

  Uint8List chacha20Decrypt(Uint8List c, Uint8List key, Uint8List iv) =>
      _cipher(ssl.EVP_chacha20(), c, key, iv, encrypt: false);

  Uint8List _cipher(
    Pointer<ssl.evp_cipher_st> cipher,
    Uint8List input,
    Uint8List key,
    Uint8List iv, {
    required bool encrypt,
  }) {
    _ensureBufs(input.length);
    _inBuf.asTypedList(input.length).setRange(0, input.length, input);
    _keyBuf.asTypedList(key.length).setRange(0, key.length, key);
    _ivBuf.asTypedList(iv.length).setRange(0, iv.length, iv);

    if (encrypt) {
      ssl.EVP_EncryptInit_ex(_cipherCtx, cipher, nullptr, _keyBuf.cast(), _ivBuf.cast());
      ssl.EVP_EncryptUpdate(_cipherCtx, _outBuf.cast(), _outLen1.cast(), _inBuf.cast(), input.length);
      ssl.EVP_EncryptFinal_ex(_cipherCtx, (_outBuf + _outLen1.value).cast(), _outLen2.cast());
    } else {
      ssl.EVP_DecryptInit_ex(_cipherCtx, cipher, nullptr, _keyBuf.cast(), _ivBuf.cast());
      ssl.EVP_DecryptUpdate(_cipherCtx, _outBuf.cast(), _outLen1.cast(), _inBuf.cast(), input.length);
      ssl.EVP_DecryptFinal_ex(_cipherCtx, (_outBuf + _outLen1.value).cast(), _outLen2.cast());
    }
    return Uint8List.fromList(_outBuf.asTypedList(_outLen1.value + _outLen2.value));
  }

  void prewarm(int size) => _ensureBufs(size);

  void dispose() {
    ssl.EVP_MD_CTX_free(_mdCtx);
    ssl.EVP_CIPHER_CTX_free(_cipherCtx);
    malloc.free(_digestBuf);
    malloc.free(_digestLen);
    malloc.free(_outLen1);
    malloc.free(_outLen2);
    malloc.free(_keyBuf);
    malloc.free(_ivBuf);
    if (_allocSize > 0) {
      malloc.free(_inBuf);
      malloc.free(_outBuf);
    }
  }
}
