/// BoringSSL FFI bindings using runtime library loading.
///
/// BoringSSL is API-compatible with OpenSSL for most operations, but it removed
/// [EVP_chacha20] from its EVP cipher API. This class uses [CRYPTO_chacha_20]
/// (BoringSSL's direct ChaCha20 API) for stream-cipher benchmarks.
///
/// The shared library (libboringssl_dart.so) is built once by running:
///   scripts/build_boringssl.sh
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'openssl_ffi.dart' show EvpMdCtx, EvpMd, EvpCipherCtx, EvpCipher;

// ---------------------------------------------------------------------------
// BoringSSL-specific typedefs
// ---------------------------------------------------------------------------

// CRYPTO_chacha_20: BoringSSL's direct ChaCha20 API (no EVP_chacha20 in BoringSSL)
// void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
//                       const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
typedef _CryptoChacha20Native = Void Function(
  Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>, Uint32);

// Shared EVP typedefs (same as OpenSSL)
typedef _MdCtxNewNative2      = Pointer<EvpMdCtx> Function();
typedef _MdCtxFreeNative2     = Void Function(Pointer<EvpMdCtx>);
typedef _Sha256Native2        = Pointer<EvpMd> Function();
typedef _DigestInitExNative2  = Int32 Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>);
typedef _DigestUpdateNative2  = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Size);
typedef _DigestFinalExNative2 = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>);
typedef _CipherCtxNewNative2  = Pointer<EvpCipherCtx> Function();
typedef _CipherCtxFreeNative2 = Void Function(Pointer<EvpCipherCtx>);
typedef _Aes256CtrNative2     = Pointer<EvpCipher> Function();
typedef _EncInitExNative2     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncUpdateNative2     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EncFinalExNative2    = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>);
typedef _RandBytesNative2     = Int32 Function(Pointer<Uint8>, Int32);

// ---------------------------------------------------------------------------
// BoringSslCrypto
// ---------------------------------------------------------------------------

class BoringSslCrypto {
  late final DynamicLibrary _lib;

  late final Pointer<EvpMdCtx> Function()                                                              _mdCtxNew;
  late final void Function(Pointer<EvpMdCtx>)                                                          _mdCtxFree;
  late final Pointer<EvpMd> Function()                                                                 _sha256;
  late final int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)                           _digestInitEx;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)                                     _digestUpdate;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)                         _digestFinalEx;
  late final Pointer<EvpCipherCtx> Function()                                                          _cipherCtxNew;
  late final void Function(Pointer<EvpCipherCtx>)                                                      _cipherCtxFree;
  late final Pointer<EvpCipher> Function()                                                             _aes256Ctr;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _encInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int) _encUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                      _encFinalEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _decInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int) _decUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                      _decFinalEx;
  late final int Function(Pointer<Uint8>, int)                                                         _randBytes;
  // BoringSSL ChaCha20 direct API (EVP_chacha20 does not exist in BoringSSL)
  late final void Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, int)  _boringChacha20;

  late final Pointer<EvpMdCtx>    _mdCtx;
  late final Pointer<EvpCipherCtx> _cipherCtx;
  late final Pointer<Uint8>  _digestBuf;
  late final Pointer<Uint32> _digestLen;
  late final Pointer<Int32>  _outLen1;
  late final Pointer<Int32>  _outLen2;
  late final Pointer<Uint8>  _keyBuf;
  late final Pointer<Uint8>  _ivBuf;
  late final Pointer<Uint8>  _nonceBuf; // 12-byte nonce for CRYPTO_chacha_20

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

  BoringSslCrypto(String libPath) {
    _lib = DynamicLibrary.open(libPath);

    _mdCtxNew     = _lib.lookupFunction<_MdCtxNewNative2,      Pointer<EvpMdCtx> Function()>('EVP_MD_CTX_new');
    _mdCtxFree    = _lib.lookupFunction<_MdCtxFreeNative2,     void Function(Pointer<EvpMdCtx>)>('EVP_MD_CTX_free');
    _sha256       = _lib.lookupFunction<_Sha256Native2,        Pointer<EvpMd> Function()>('EVP_sha256');
    _digestInitEx = _lib.lookupFunction<_DigestInitExNative2,  int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)>('EVP_DigestInit_ex');
    _digestUpdate = _lib.lookupFunction<_DigestUpdateNative2,  int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)>('EVP_DigestUpdate');
    _digestFinalEx= _lib.lookupFunction<_DigestFinalExNative2, int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)>('EVP_DigestFinal_ex');

    _cipherCtxNew = _lib.lookupFunction<_CipherCtxNewNative2,  Pointer<EvpCipherCtx> Function()>('EVP_CIPHER_CTX_new');
    _cipherCtxFree= _lib.lookupFunction<_CipherCtxFreeNative2, void Function(Pointer<EvpCipherCtx>)>('EVP_CIPHER_CTX_free');
    _aes256Ctr    = _lib.lookupFunction<_Aes256CtrNative2,     Pointer<EvpCipher> Function()>('EVP_aes_256_ctr');
    _encInitEx    = _lib.lookupFunction<_EncInitExNative2,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_EncryptInit_ex');
    _encUpdate    = _lib.lookupFunction<_EncUpdateNative2,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_EncryptUpdate');
    _encFinalEx   = _lib.lookupFunction<_EncFinalExNative2,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_EncryptFinal_ex');
    _decInitEx    = _lib.lookupFunction<_EncInitExNative2,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_DecryptInit_ex');
    _decUpdate    = _lib.lookupFunction<_EncUpdateNative2,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_DecryptUpdate');
    _decFinalEx   = _lib.lookupFunction<_EncFinalExNative2,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_DecryptFinal_ex');
    _randBytes    = _lib.lookupFunction<_RandBytesNative2,     int Function(Pointer<Uint8>, int)>('RAND_bytes');
    _boringChacha20 = _lib.lookupFunction<
      _CryptoChacha20Native,
      void Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, int)
    >('CRYPTO_chacha_20');

    _mdCtx      = _mdCtxNew();
    _cipherCtx  = _cipherCtxNew();
    _digestBuf  = malloc.allocate<Uint8>(32);
    _digestLen  = malloc.allocate<Uint32>(1);
    _outLen1    = malloc.allocate<Int32>(1);
    _outLen2    = malloc.allocate<Int32>(1);
    _keyBuf     = malloc.allocate<Uint8>(64);
    _ivBuf      = malloc.allocate<Uint8>(32);
    _nonceBuf   = malloc.allocate<Uint8>(12);
  }

  Uint8List sha256(Uint8List data) {
    _ensureBufs(data.length);
    _inBuf.asTypedList(data.length).setRange(0, data.length, data);
    _digestInitEx(_mdCtx, _sha256(), nullptr);
    _digestUpdate(_mdCtx, _inBuf, data.length);
    _digestFinalEx(_mdCtx, _digestBuf, _digestLen);
    return Uint8List.fromList(_digestBuf.asTypedList(32));
  }

  Uint8List aes256CtrEncrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
      _aesCipher(plaintext, key, iv, encrypt: true);

  Uint8List aes256CtrDecrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
      _aesCipher(ciphertext, key, iv, encrypt: false);

  /// ChaCha20 via BoringSSL's [CRYPTO_chacha_20].
  ///
  /// [iv] layout: [4-byte counter LE][12-byte nonce] — same convention as
  /// OpenSSL's EVP_chacha20, so keys/IVs are interchangeable between implementations.
  Uint8List chacha20Encrypt(Uint8List plaintext, Uint8List key, Uint8List iv) {
    _ensureBufs(plaintext.length);
    _inBuf.asTypedList(plaintext.length).setRange(0, plaintext.length, plaintext);
    _keyBuf.asTypedList(32).setRange(0, 32, key);
    // Extract counter from first 4 bytes (little-endian)
    final counter = iv[0] | (iv[1] << 8) | (iv[2] << 16) | (iv[3] << 24);
    // Copy 12-byte nonce (bytes 4-15 of iv)
    _nonceBuf.asTypedList(12).setRange(0, 12, iv.sublist(4, 16));
    _boringChacha20(_outBuf, _inBuf, plaintext.length, _keyBuf, _nonceBuf, counter);
    return Uint8List.fromList(_outBuf.asTypedList(plaintext.length));
  }

  // ChaCha20 is its own inverse
  Uint8List chacha20Decrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
      chacha20Encrypt(ciphertext, key, iv);

  Uint8List randBytes(int n) {
    _ensureBufs(n);
    final rc = _randBytes(_outBuf, n);
    if (rc != 1) throw StateError('RAND_bytes failed (rc=$rc)');
    return Uint8List.fromList(_outBuf.asTypedList(n));
  }

  Uint8List _aesCipher(Uint8List input, Uint8List key, Uint8List iv, {required bool encrypt}) {
    _ensureBufs(input.length);
    _inBuf.asTypedList(input.length).setRange(0, input.length, input);
    _keyBuf.asTypedList(key.length).setRange(0, key.length, key);
    _ivBuf.asTypedList(iv.length).setRange(0, iv.length, iv);
    final cipher = _aes256Ctr();
    if (encrypt) {
      _encInitEx(_cipherCtx, cipher, nullptr, _keyBuf, _ivBuf);
      _encUpdate(_cipherCtx, _outBuf, _outLen1, _inBuf, input.length);
      _encFinalEx(_cipherCtx, _outBuf + _outLen1.value, _outLen2);
    } else {
      _decInitEx(_cipherCtx, cipher, nullptr, _keyBuf, _ivBuf);
      _decUpdate(_cipherCtx, _outBuf, _outLen1, _inBuf, input.length);
      _decFinalEx(_cipherCtx, _outBuf + _outLen1.value, _outLen2);
    }
    final total = _outLen1.value + _outLen2.value;
    return Uint8List.fromList(_outBuf.asTypedList(total));
  }

  void prewarm(int size) => _ensureBufs(size);

  void dispose() {
    _mdCtxFree(_mdCtx);
    _cipherCtxFree(_cipherCtx);
    malloc.free(_digestBuf);
    malloc.free(_digestLen);
    malloc.free(_outLen1);
    malloc.free(_outLen2);
    malloc.free(_keyBuf);
    malloc.free(_ivBuf);
    malloc.free(_nonceBuf);
    if (_allocSize > 0) {
      malloc.free(_inBuf);
      malloc.free(_outBuf);
    }
  }
}

// ---------------------------------------------------------------------------
// Path resolution for libboringssl_dart
// ---------------------------------------------------------------------------

/// Returns the path to the libboringssl_dart shared library.
///
/// Search order:
/// 1. Native Assets output (.dart_tool/hooks_runner/shared/boringssl/) — set up
///    automatically by [dart run] / [dart build] via the packages/boringssl hook.
/// 2. build/ — output of scripts/build_boringssl.sh (manual fallback).
/// 3. Next to the current executable (compiled dart build output).
String getBoringSslLibPath() {
  final libName = Platform.isWindows ? 'boringssl_dart.dll'
                : Platform.isMacOS  ? 'libboringssl_dart.dylib'
                : 'libboringssl_dart.so';

  final base    = Directory.current.path;
  final execDir = File(Platform.resolvedExecutable).parent.path;

  final candidates = [
    // Native Assets output: .dart_tool/hooks_runner/shared/boringssl/build/
    '$base/.dart_tool/hooks_runner/shared/boringssl/build/$libName',
    // Manual build script output
    '$base/build/$libName',
    // Compiled bundle (dart build cli output)
    '$execDir/$libName',
    '$execDir/../lib/$libName',
  ];

  for (final p in candidates) {
    if (File(p).existsSync()) return p;
  }
  throw StateError(
    '$libName not found.\n'
    'It is built automatically by the Native Assets hook when you run:\n'
    '  dart pub get && dart run bin/speedtest.dart ...\n'
    'Requires webcrypto in pub cache: dart pub cache add webcrypto:0.5.8\n'
    'Or build manually: bash scripts/build_boringssl.sh',
  );
}
