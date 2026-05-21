/// OpenSSL FFI bindings using runtime library loading.
///
/// ## Approach: runtime DynamicLibrary.open()
///
/// This file loads the *system* libcrypto at runtime via [DynamicLibrary.open].
/// No build tools are required; the library is resolved from the OS at startup.
///
/// ### Compared with the `openssl` pub package (pub.dev/packages/openssl)
///
/// The `openssl` package uses Dart *Native Assets* (Dart ≥ 3.10.1 + cmake) to
/// compile and bundle its own OpenSSL from source at `dart build` time.
/// Both approaches ultimately call the same OpenSSL EVP C functions — the
/// difference is entirely in *how and when* the library is linked:
///
/// | Aspect               | This file (runtime)        | openssl package (build-time)   |
/// |----------------------|----------------------------|--------------------------------|
/// | Dart SDK required    | any dart:ffi version       | ≥ 3.10.1                       |
/// | Build tools needed   | none                       | cmake + C toolchain            |
/// | First-build time     | instant                    | ~1 min (compiles from source)  |
/// | OpenSSL source       | OS-provided                | bundled, fixed version         |
/// | Binary portability   | needs system OpenSSL       | fully self-contained           |
/// | Cross-architecture   | automatic (OS handles it)  | must cross-compile             |
/// | API surface          | hand-crafted EVP wrapper   | full auto-generated C bindings |
///
/// ### What the openssl package code looks like
///
/// The openssl package exposes the raw C EVP API through auto-generated
/// bindings (identical function names, identical semantics):
///
/// ```dart
/// import 'package:openssl/openssl.dart' as ssl;
///
/// // Identical EVP calls, but the library was compiled into the binary:
/// final ctx = ssl.EVP_MD_CTX_new();
/// ssl.EVP_DigestInit_ex(ctx, ssl.EVP_sha256(), nullptr);
/// ssl.EVP_DigestUpdate(ctx, dataPtr, dataLen);
/// ssl.EVP_DigestFinal_ex(ctx, digestPtr, digestLenPtr);
/// ssl.EVP_MD_CTX_free(ctx);
/// ```
///
/// Because the API is identical, [OpenSslCrypto] could be adapted to use the
/// openssl package's bindings by swapping [DynamicLibrary.open] for the
/// package's generated lookup table — no algorithmic changes required.

library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// Opaque C types
// ---------------------------------------------------------------------------

final class EvpMdCtx extends Opaque {}
final class EvpMd extends Opaque {}
final class EvpCipherCtx extends Opaque {}
final class EvpCipher extends Opaque {}

// ---------------------------------------------------------------------------
// Native typedef pairs (C signature / Dart signature)
// ---------------------------------------------------------------------------

// Digest context lifecycle
typedef _MdCtxNewNative      = Pointer<EvpMdCtx> Function();
typedef _MdCtxFreeNative     = Void Function(Pointer<EvpMdCtx>);

// SHA-256 descriptor + digest operations
typedef _Sha256Native        = Pointer<EvpMd> Function();
typedef _DigestInitExNative  = Int32 Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>);
typedef _DigestUpdateNative  = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Size);
typedef _DigestFinalExNative = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>);

// Cipher context lifecycle
typedef _CipherCtxNewNative  = Pointer<EvpCipherCtx> Function();
typedef _CipherCtxFreeNative = Void Function(Pointer<EvpCipherCtx>);

// Cipher descriptors
typedef _Aes256CtrNative     = Pointer<EvpCipher> Function();
typedef _Chacha20Native      = Pointer<EvpCipher> Function();

// Encrypt operations
typedef _EncInitExNative     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncUpdateNative     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EncFinalExNative    = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>);

// Decrypt operations (same shape, different symbol names)
typedef _DecInitExNative     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _DecUpdateNative     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _DecFinalExNative    = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>);

// Random bytes — RAND_bytes fills a buffer using the OS entropy source
// (RDRAND / RDSEED on x86, getrandom on Linux). Returns 1 on success.
typedef _RandBytesNative     = Int32 Function(Pointer<Uint8>, Int32);

// ---------------------------------------------------------------------------
// OpenSslCrypto
//
// All EVP contexts and I/O buffers are allocated once and reused across calls.
// The only per-call allocation is the Dart-side Uint8List copy of the output.
// ---------------------------------------------------------------------------

class OpenSslCrypto {
  late final DynamicLibrary _lib;

  // Bound C functions
  late final Pointer<EvpMdCtx> Function()                                                              _mdCtxNew;
  late final void Function(Pointer<EvpMdCtx>)                                                          _mdCtxFree;
  late final Pointer<EvpMd> Function()                                                                 _sha256;
  late final int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)                           _digestInitEx;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)                                     _digestUpdate;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)                         _digestFinalEx;

  late final Pointer<EvpCipherCtx> Function()                                                          _cipherCtxNew;
  late final void Function(Pointer<EvpCipherCtx>)                                                      _cipherCtxFree;
  late final Pointer<EvpCipher> Function()                                                             _aes256Ctr;
  late final Pointer<EvpCipher> Function()                                                             _chacha20;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _encInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int) _encUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                      _encFinalEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _decInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int) _decUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                      _decFinalEx;
  late final int Function(Pointer<Uint8>, int)                                                         _randBytes;

  // Persistent contexts — allocated once, reset on each call via Init_ex.
  late final Pointer<EvpMdCtx>    _mdCtx;
  late final Pointer<EvpCipherCtx> _cipherCtx;

  // Persistent fixed-size scratch buffers.
  late final Pointer<Uint8>  _digestBuf; // 32 bytes for SHA-256 output
  late final Pointer<Uint32> _digestLen;
  late final Pointer<Int32>  _outLen1;
  late final Pointer<Int32>  _outLen2;
  late final Pointer<Uint8>  _keyBuf;    // 64 bytes – supports any key size
  late final Pointer<Uint8>  _ivBuf;     // 32 bytes – supports any IV size

  // Dynamically-sized I/O buffers; grown lazily, never shrunk.
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
    _outBuf    = malloc.allocate<Uint8>(size + 64); // +64 for any cipher padding
    _allocSize = size;
  }

  OpenSslCrypto(String libPath) {
    _lib = DynamicLibrary.open(libPath);

    _mdCtxNew     = _lib.lookupFunction<_MdCtxNewNative,      Pointer<EvpMdCtx> Function()>('EVP_MD_CTX_new');
    _mdCtxFree    = _lib.lookupFunction<_MdCtxFreeNative,     void Function(Pointer<EvpMdCtx>)>('EVP_MD_CTX_free');
    _sha256       = _lib.lookupFunction<_Sha256Native,        Pointer<EvpMd> Function()>('EVP_sha256');
    _digestInitEx = _lib.lookupFunction<_DigestInitExNative,  int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)>('EVP_DigestInit_ex');
    _digestUpdate = _lib.lookupFunction<_DigestUpdateNative,  int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)>('EVP_DigestUpdate');
    _digestFinalEx= _lib.lookupFunction<_DigestFinalExNative, int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)>('EVP_DigestFinal_ex');

    _cipherCtxNew = _lib.lookupFunction<_CipherCtxNewNative,  Pointer<EvpCipherCtx> Function()>('EVP_CIPHER_CTX_new');
    _cipherCtxFree= _lib.lookupFunction<_CipherCtxFreeNative, void Function(Pointer<EvpCipherCtx>)>('EVP_CIPHER_CTX_free');
    _aes256Ctr    = _lib.lookupFunction<_Aes256CtrNative,     Pointer<EvpCipher> Function()>('EVP_aes_256_ctr');
    _chacha20     = _lib.lookupFunction<_Chacha20Native,      Pointer<EvpCipher> Function()>('EVP_chacha20');
    _encInitEx    = _lib.lookupFunction<_EncInitExNative,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_EncryptInit_ex');
    _encUpdate    = _lib.lookupFunction<_EncUpdateNative,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_EncryptUpdate');
    _encFinalEx   = _lib.lookupFunction<_EncFinalExNative,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_EncryptFinal_ex');
    _decInitEx    = _lib.lookupFunction<_DecInitExNative,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_DecryptInit_ex');
    _decUpdate    = _lib.lookupFunction<_DecUpdateNative,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_DecryptUpdate');
    _decFinalEx   = _lib.lookupFunction<_DecFinalExNative,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_DecryptFinal_ex');
    _randBytes    = _lib.lookupFunction<_RandBytesNative,     int Function(Pointer<Uint8>, int)>('RAND_bytes');

    _mdCtx      = _mdCtxNew();
    _cipherCtx  = _cipherCtxNew();
    _digestBuf  = malloc.allocate<Uint8>(32);
    _digestLen  = malloc.allocate<Uint32>(1);
    _outLen1    = malloc.allocate<Int32>(1);
    _outLen2    = malloc.allocate<Int32>(1);
    _keyBuf     = malloc.allocate<Uint8>(64);
    _ivBuf      = malloc.allocate<Uint8>(32);
  }

  /// SHA-256 of [data]. Returns a fresh 32-byte [Uint8List].
  Uint8List sha256(Uint8List data) {
    _ensureBufs(data.length);
    _inBuf.asTypedList(data.length).setRange(0, data.length, data);
    _digestInitEx(_mdCtx, _sha256(), nullptr);
    _digestUpdate(_mdCtx, _inBuf, data.length);
    _digestFinalEx(_mdCtx, _digestBuf, _digestLen);
    return Uint8List.fromList(_digestBuf.asTypedList(32));
  }

  /// AES-256-CTR encrypt. [key] must be 32 bytes, [iv] 16 bytes.
  Uint8List aes256CtrEncrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
      _cipher(_aes256Ctr, plaintext, key, iv, encrypt: true);

  /// AES-256-CTR decrypt. [key] must be 32 bytes, [iv] 16 bytes.
  Uint8List aes256CtrDecrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
      _cipher(_aes256Ctr, ciphertext, key, iv, encrypt: false);

  /// ChaCha20 encrypt. [key] must be 32 bytes, [iv] 16 bytes
  /// (EVP_chacha20 layout: 4-byte counter || 12-byte nonce).
  Uint8List chacha20Encrypt(Uint8List plaintext, Uint8List key, Uint8List iv) =>
      _cipher(_chacha20, plaintext, key, iv, encrypt: true);

  /// ChaCha20 decrypt. Same key/iv layout as [chacha20Encrypt].
  Uint8List chacha20Decrypt(Uint8List ciphertext, Uint8List key, Uint8List iv) =>
      _cipher(_chacha20, ciphertext, key, iv, encrypt: false);

  /// Fill [n] bytes from OpenSSL's CSPRNG (RDRAND/RDSEED on x86, getrandom on Linux).
  /// Throws [StateError] if RAND_bytes reports failure.
  Uint8List randBytes(int n) {
    _ensureBufs(n);
    final rc = _randBytes(_outBuf, n);
    if (rc != 1) throw StateError('RAND_bytes failed (rc=$rc)');
    return Uint8List.fromList(_outBuf.asTypedList(n));
  }

  Uint8List _cipher(
    Pointer<EvpCipher> Function() cipherFn,
    Uint8List input,
    Uint8List key,
    Uint8List iv, {
    required bool encrypt,
  }) {
    _ensureBufs(input.length);
    // setRange over a native-memory typed-list view → maps to a single memcpy.
    _inBuf.asTypedList(input.length).setRange(0, input.length, input);
    _keyBuf.asTypedList(key.length).setRange(0, key.length, key);
    _ivBuf.asTypedList(iv.length).setRange(0, iv.length, iv);

    final cipher = cipherFn();
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

  /// Pre-grows the I/O buffers to [size] bytes.
  /// Call this before the first timed operation to exclude allocation from
  /// benchmark measurements.
  void prewarm(int size) => _ensureBufs(size);

  /// Releases all native memory. Must be called when finished.
  void dispose() {
    _mdCtxFree(_mdCtx);
    _cipherCtxFree(_cipherCtx);
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

// ---------------------------------------------------------------------------
// Platform path resolution for libcrypto
// ---------------------------------------------------------------------------

/// Returns the best available path to libcrypto on the current platform.
///
/// Searches common installation paths in priority order. On Linux, covers
/// x86_64 (Intel/AMD) and aarch64 (Graviton/Apple Silicon Linux) layouts.
String getOpenSslLibPath() {
  if (Platform.isMacOS) {
    for (final p in [
      '/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib', // Apple Silicon Homebrew
      '/usr/local/opt/openssl@3/lib/libcrypto.dylib',    // Intel Homebrew
      '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
    ]) {
      if (File(p).existsSync()) return p;
    }
    return 'libcrypto.dylib';
  }

  if (Platform.isLinux) {
    for (final p in [
      // x86_64 (Intel / AMD)
      '/lib/x86_64-linux-gnu/libcrypto.so.3',
      '/lib/x86_64-linux-gnu/libcrypto.so',
      '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
      '/usr/lib/libcrypto.so.3',
      '/usr/local/lib/libcrypto.so.3',
      // aarch64 (AWS Graviton, Raspberry Pi 64-bit, Apple Silicon Linux)
      '/lib/aarch64-linux-gnu/libcrypto.so.3',
      '/lib/aarch64-linux-gnu/libcrypto.so',
      '/usr/lib/aarch64-linux-gnu/libcrypto.so.3',
    ]) {
      if (File(p).existsSync()) return p;
    }
    return 'libcrypto.so';
  }

  if (Platform.isWindows) return 'libcrypto-3-x64.dll';

  return 'libcrypto';
}
