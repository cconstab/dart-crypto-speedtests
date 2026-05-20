/// Standalone OpenSSL FFI benchmark.
///
/// Loads the system libcrypto at runtime via dart:ffi. No Native Assets,
/// no Flutter, no build toolchain — just Dart and a system OpenSSL install.
///
/// Build:  dart compile exe bin/opensslbench.dart -o opensslbench
/// Run:    ./opensslbench <size_mb> <repeat>
///
/// If libcrypto is not found the binary exits with a clear install message.
/// Supported platforms: Linux x86_64, Linux aarch64, macOS, Windows.

import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:chalk/chalk.dart';
import 'package:collection/collection.dart';
import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// Opaque C types
// ---------------------------------------------------------------------------

final class EvpMdCtx     extends Opaque {}
final class EvpMd        extends Opaque {}
final class EvpCipherCtx extends Opaque {}
final class EvpCipher    extends Opaque {}

// ---------------------------------------------------------------------------
// Native typedef pairs
// ---------------------------------------------------------------------------

typedef _MdCtxNewN       = Pointer<EvpMdCtx>     Function();
typedef _MdCtxFreeN      = Void                  Function(Pointer<EvpMdCtx>);
typedef _Sha256N         = Pointer<EvpMd>         Function();
typedef _DigestInitExN   = Int32 Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>);
typedef _DigestUpdateN   = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Size);
typedef _DigestFinalExN  = Int32 Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>);
typedef _CipherCtxNewN   = Pointer<EvpCipherCtx>  Function();
typedef _CipherCtxFreeN  = Void                  Function(Pointer<EvpCipherCtx>);
typedef _CipherN         = Pointer<EvpCipher>     Function();
typedef _EncInitExN      = Int32 Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncUpdateN      = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EncFinalExN     = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>);

// ---------------------------------------------------------------------------
// OpenSslCrypto — persistent EVP contexts, zero-alloc hot path
// ---------------------------------------------------------------------------

class OpenSslCrypto {
  late final Pointer<EvpMdCtx>    Function()                                                                 _mdCtxNew;
  late final void                 Function(Pointer<EvpMdCtx>)                                               _mdCtxFree;
  late final Pointer<EvpMd>       Function()                                                                 _sha256fn;
  late final int                  Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)                _digestInitEx;
  late final int                  Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)                          _digestUpdate;
  late final int                  Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)              _digestFinalEx;
  late final Pointer<EvpCipherCtx> Function()                                                                _cipherCtxNew;
  late final void                 Function(Pointer<EvpCipherCtx>)                                           _cipherCtxFree;
  late final Pointer<EvpCipher>   Function()                                                                 _aes256Ctr;
  late final Pointer<EvpCipher>   Function()                                                                 _chacha20fn;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _encInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)       _encUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                            _encFinalEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _decInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)       _decUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)                            _decFinalEx;

  late final Pointer<EvpMdCtx>     _mdCtx;
  late final Pointer<EvpCipherCtx> _cipherCtx;
  late final Pointer<Uint8>  _digestBuf;
  late final Pointer<Uint32> _digestLen;
  late final Pointer<Int32>  _outLen1, _outLen2;
  late final Pointer<Uint8>  _keyBuf, _ivBuf;

  Pointer<Uint8> _inBuf  = nullptr;
  Pointer<Uint8> _outBuf = nullptr;
  int _allocSize = 0;

  void _ensureBufs(int size) {
    if (size <= _allocSize) return;
    if (_allocSize > 0) { malloc.free(_inBuf); malloc.free(_outBuf); }
    _inBuf     = malloc.allocate<Uint8>(size);
    _outBuf    = malloc.allocate<Uint8>(size + 64);
    _allocSize = size;
  }

  OpenSslCrypto(String libPath) {
    final lib = DynamicLibrary.open(libPath);

    _mdCtxNew      = lib.lookupFunction<_MdCtxNewN,      Pointer<EvpMdCtx>     Function()>('EVP_MD_CTX_new');
    _mdCtxFree     = lib.lookupFunction<_MdCtxFreeN,     void Function(Pointer<EvpMdCtx>)>('EVP_MD_CTX_free');
    _sha256fn      = lib.lookupFunction<_Sha256N,        Pointer<EvpMd>        Function()>('EVP_sha256');
    _digestInitEx  = lib.lookupFunction<_DigestInitExN,  int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)>('EVP_DigestInit_ex');
    _digestUpdate  = lib.lookupFunction<_DigestUpdateN,  int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int)>('EVP_DigestUpdate');
    _digestFinalEx = lib.lookupFunction<_DigestFinalExN, int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)>('EVP_DigestFinal_ex');
    _cipherCtxNew  = lib.lookupFunction<_CipherCtxNewN,  Pointer<EvpCipherCtx> Function()>('EVP_CIPHER_CTX_new');
    _cipherCtxFree = lib.lookupFunction<_CipherCtxFreeN, void Function(Pointer<EvpCipherCtx>)>('EVP_CIPHER_CTX_free');
    _aes256Ctr     = lib.lookupFunction<_CipherN,        Pointer<EvpCipher>    Function()>('EVP_aes_256_ctr');
    _chacha20fn    = lib.lookupFunction<_CipherN,        Pointer<EvpCipher>    Function()>('EVP_chacha20');
    _encInitEx     = lib.lookupFunction<_EncInitExN,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_EncryptInit_ex');
    _encUpdate     = lib.lookupFunction<_EncUpdateN,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_EncryptUpdate');
    _encFinalEx    = lib.lookupFunction<_EncFinalExN,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_EncryptFinal_ex');
    _decInitEx     = lib.lookupFunction<_EncInitExN,     int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>('EVP_DecryptInit_ex');
    _decUpdate     = lib.lookupFunction<_EncUpdateN,     int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int)>('EVP_DecryptUpdate');
    _decFinalEx    = lib.lookupFunction<_EncFinalExN,    int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)>('EVP_DecryptFinal_ex');

    _mdCtx      = _mdCtxNew();
    _cipherCtx  = _cipherCtxNew();
    _digestBuf  = malloc.allocate<Uint8>(32);
    _digestLen  = malloc.allocate<Uint32>(1);
    _outLen1    = malloc.allocate<Int32>(1);
    _outLen2    = malloc.allocate<Int32>(1);
    _keyBuf     = malloc.allocate<Uint8>(64);
    _ivBuf      = malloc.allocate<Uint8>(32);
  }

  Uint8List sha256(Uint8List data) {
    _ensureBufs(data.length);
    _inBuf.asTypedList(data.length).setRange(0, data.length, data);
    _digestInitEx(_mdCtx, _sha256fn(), nullptr);
    _digestUpdate(_mdCtx, _inBuf, data.length);
    _digestFinalEx(_mdCtx, _digestBuf, _digestLen);
    return Uint8List.fromList(_digestBuf.asTypedList(32));
  }

  Uint8List aes256CtrEncrypt(Uint8List p, Uint8List key, Uint8List iv) => _cipher(_aes256Ctr,  p,   key, iv, enc: true);
  Uint8List aes256CtrDecrypt(Uint8List c, Uint8List key, Uint8List iv) => _cipher(_aes256Ctr,  c,   key, iv, enc: false);
  Uint8List chacha20Encrypt (Uint8List p, Uint8List key, Uint8List iv) => _cipher(_chacha20fn, p,   key, iv, enc: true);
  Uint8List chacha20Decrypt (Uint8List c, Uint8List key, Uint8List iv) => _cipher(_chacha20fn, c,   key, iv, enc: false);

  Uint8List _cipher(Pointer<EvpCipher> Function() fn, Uint8List input, Uint8List key, Uint8List iv, {required bool enc}) {
    _ensureBufs(input.length);
    _inBuf.asTypedList(input.length).setRange(0, input.length, input);
    _keyBuf.asTypedList(key.length).setRange(0, key.length, key);
    _ivBuf.asTypedList(iv.length).setRange(0, iv.length, iv);
    final cipher = fn();
    if (enc) {
      _encInitEx(_cipherCtx, cipher, nullptr, _keyBuf, _ivBuf);
      _encUpdate(_cipherCtx, _outBuf, _outLen1, _inBuf, input.length);
      _encFinalEx(_cipherCtx, _outBuf + _outLen1.value, _outLen2);
    } else {
      _decInitEx(_cipherCtx, cipher, nullptr, _keyBuf, _ivBuf);
      _decUpdate(_cipherCtx, _outBuf, _outLen1, _inBuf, input.length);
      _decFinalEx(_cipherCtx, _outBuf + _outLen1.value, _outLen2);
    }
    return Uint8List.fromList(_outBuf.asTypedList(_outLen1.value + _outLen2.value));
  }

  void prewarm(int size) => _ensureBufs(size);

  void dispose() {
    _mdCtxFree(_mdCtx);
    _cipherCtxFree(_cipherCtx);
    for (final p in [_digestBuf, _keyBuf, _ivBuf]) malloc.free(p);
    malloc.free(_digestLen);
    malloc.free(_outLen1);
    malloc.free(_outLen2);
    if (_allocSize > 0) { malloc.free(_inBuf); malloc.free(_outBuf); }
  }
}

// ---------------------------------------------------------------------------
// Platform path resolution
// ---------------------------------------------------------------------------

String _libPath() {
  if (Platform.isMacOS) {
    for (final p in [
      '/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib',
      '/usr/local/opt/openssl@3/lib/libcrypto.dylib',
      '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
    ]) {
      if (File(p).existsSync()) return p;
    }
    return 'libcrypto.dylib';
  }
  if (Platform.isLinux) {
    for (final p in [
      '/lib/x86_64-linux-gnu/libcrypto.so.3',
      '/lib/x86_64-linux-gnu/libcrypto.so',
      '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
      '/usr/lib/libcrypto.so.3',
      '/usr/local/lib/libcrypto.so.3',
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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

void main(List<String> args) {
  if (args.length != 2) {
    print('Usage: opensslbench <size_mb> <repeat>');
    exit(1);
  }
  final mBytes = int.parse(args[0]) * 1024 * 1024;
  final repeat = int.parse(args[1]);
  final input  = _randomBytes(mBytes);

  _printCpuFeatures();

  final path = _libPath();
  OpenSslCrypto ffi;
  try {
    ffi = OpenSslCrypto(path);
    ffi.prewarm(input.length);
    print('OpenSSL : $path');
  } catch (e) {
    print(chalk.red('Could not load OpenSSL from "$path"'));
    print(chalk.yellow(_installHint()));
    exit(1);
  }

  final results = <_Result>[];
  final warmups = min(2, repeat);

  // SHA-256
  _section('SHA-256  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_bench('SHA-256', input, repeat, warmups, () => ffi.sha256(input)));

  // AES-256-CTR
  final aesKey = _randomBytes(32);
  final aesIv  = _randomBytes(16);
  _section('AES-256-CTR  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_benchRt('AES-256-CTR', input, repeat, warmups, () {
    final enc = ffi.aes256CtrEncrypt(input, aesKey, aesIv);
    return ffi.aes256CtrDecrypt(enc, aesKey, aesIv);
  }));

  // ChaCha20
  final chaKey = _randomBytes(32);
  final chaIv  = _randomBytes(16);
  _section('ChaCha20  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_benchRt('ChaCha20', input, repeat, warmups, () {
    final enc = ffi.chacha20Encrypt(input, chaKey, chaIv);
    return ffi.chacha20Decrypt(enc, chaKey, chaIv);
  }));

  ffi.dispose();
  _printSummary(results, mBytes, repeat);
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

_Result _bench(String name, Uint8List input, int repeat, int warmups, void Function() fn) {
  for (var i = 0; i < warmups; i++) fn();
  final sw = Stopwatch()..start();
  for (var i = 0; i < repeat; i++) { fn(); stdout.write('.'); }
  sw.stop();
  return _finish(name, input, repeat, sw.elapsedMilliseconds);
}

_Result _benchRt(String name, Uint8List input, int repeat, int warmups, Uint8List Function() fn) {
  for (var i = 0; i < warmups; i++) fn();
  final sw = Stopwatch()..start();
  bool ok = true;
  for (var i = 0; i < repeat; i++) {
    final out = fn();
    if (!const ListEquality<int>().equals(out, input)) ok = false;
    stdout.write(ok ? '.' : chalk.red('!'));
  }
  sw.stop();
  if (!ok) print(chalk.red('  ROUNDTRIP MISMATCH'));
  return _finish(name, input, repeat, sw.elapsedMilliseconds);
}

_Result _finish(String name, Uint8List input, int repeat, int ms) {
  final mbps = ms == 0 ? 0 : (((input.length * 8 * repeat) / 1e6) / (ms / 1000)).round();
  print('  ${chalk.green('$mbps mbps')}  ($ms ms)');
  return _Result(name, mbps, ms);
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

void _printSummary(List<_Result> results, int mBytes, int repeat) {
  print('');
  print(chalk.blue('=' * 60));
  print(chalk.blue('OPENSSL FFI BENCHMARK — ${Platform.operatingSystem.toUpperCase()}'));
  print(chalk.blue('=' * 60));
  print('  Data: ${mBytes ~/ (1024 * 1024)} MB   Iterations: $repeat');
  print('');
  print('┌──────────────────┬─────────────┬───────────────┐');
  print('│ Algorithm        │   Time (ms) │  Speed (mbps) │');
  print('├──────────────────┼─────────────┼───────────────┤');
  for (final r in results) {
    print('│ ${r.name.padRight(16)} │ ${r.ms.toString().padLeft(11)} │ ${r.mbps.toString().padLeft(13)} │');
  }
  print('└──────────────────┴─────────────┴───────────────┘');
  print(chalk.blue('=' * 60));
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

void _section(String title) => print('\n${chalk.cyan('── $title')}');

void _printCpuFeatures() {
  if (!Platform.isLinux) return;
  try {
    final cpuinfo = File('/proc/cpuinfo').readAsStringSync();
    final line = cpuinfo.split('\n').firstWhere(
      (l) => l.startsWith('flags') || l.startsWith('Features'), orElse: () => '');
    final flags = line.split(':').last.trim().split(' ').toSet();
    final hw = ['aes', 'sha_ni', 'avx2', 'avx512f', 'neon'].where(flags.contains).toList();
    print(chalk.cyan(hw.isEmpty
        ? 'CPU: no hw-accel flags detected'
        : 'CPU hw-accel : ${hw.join(', ')}'));
  } catch (_) {}
}

String _installHint() {
  if (Platform.isLinux)  return 'Install: sudo apt-get install libssl-dev  (or equivalent)';
  if (Platform.isMacOS)  return 'Install: brew install openssl@3';
  if (Platform.isWindows)return 'Download Win64 OpenSSL from https://slproweb.com/products/Win32OpenSSL.html';
  return 'Install OpenSSL for your platform.';
}

Uint8List _randomBytes(int n) {
  final rng = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
}

class _Result {
  final String name;
  final int    mbps;
  final int    ms;
  _Result(this.name, this.mbps, this.ms);
}
