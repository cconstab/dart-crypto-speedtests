/// Standalone OpenSSL FFI benchmark.
///
/// Loads the system libcrypto at runtime via dart:ffi. No Native Assets,
/// no Flutter, no build toolchain — just Dart and a system OpenSSL install.
///
/// Build:  dart compile exe bin/opensslbench.dart -o opensslbench
/// Run:    ./opensslbench <size_mb> <repeat> [--threads N]
///         --threads N: run concurrent throughput section with N isolates
///
/// If libcrypto is not found the binary exits with a clear install message.
/// Supported platforms: Linux x86_64, Linux aarch64, macOS, Windows.

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:chalk/chalk.dart';
import 'package:collection/collection.dart';
import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// Opaque C types
// ---------------------------------------------------------------------------

final class EvpMdCtx extends Opaque {}

final class EvpMd extends Opaque {}

final class EvpCipherCtx extends Opaque {}

final class EvpCipher extends Opaque {}

// ---------------------------------------------------------------------------
// Native typedef pairs
// ---------------------------------------------------------------------------

typedef _MdCtxNewN = Pointer<EvpMdCtx> Function();
typedef _MdCtxFreeN = Void Function(Pointer<EvpMdCtx>);
typedef _Sha256N = Pointer<EvpMd> Function();
typedef _DigestInitExN = Int32 Function(
    Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>);
typedef _DigestUpdateN = Int32 Function(
    Pointer<EvpMdCtx>, Pointer<Uint8>, Size);
typedef _DigestFinalExN = Int32 Function(
    Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>);
typedef _CipherCtxNewN = Pointer<EvpCipherCtx> Function();
typedef _CipherCtxFreeN = Void Function(Pointer<EvpCipherCtx>);
typedef _CipherN = Pointer<EvpCipher> Function();
typedef _EncInitExN = Int32 Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>,
    Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EncUpdateN = Int32 Function(Pointer<EvpCipherCtx>, Pointer<Uint8>,
    Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EncFinalExN = Int32 Function(
    Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>);
typedef _RandBytesN = Int32 Function(Pointer<Uint8>, Int32);

// ---------------------------------------------------------------------------
// OpenSslCrypto — persistent EVP contexts, zero-alloc hot path
// ---------------------------------------------------------------------------

class OpenSslCrypto {
  late final Pointer<EvpMdCtx> Function() _mdCtxNew;
  late final void Function(Pointer<EvpMdCtx>) _mdCtxFree;
  late final Pointer<EvpMd> Function() _sha256fn;
  late final int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>, Pointer<Void>)
      _digestInitEx;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int) _digestUpdate;
  late final int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Uint32>)
      _digestFinalEx;
  late final Pointer<EvpCipherCtx> Function() _cipherCtxNew;
  late final void Function(Pointer<EvpCipherCtx>) _cipherCtxFree;
  late final Pointer<EvpCipher> Function() _aes256Ctr;
  late final Pointer<EvpCipher> Function() _chacha20fn;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>,
      Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _encInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>,
      Pointer<Uint8>, int) _encUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)
      _encFinalEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>,
      Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>) _decInitEx;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>,
      Pointer<Uint8>, int) _decUpdate;
  late final int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>)
      _decFinalEx;
  late final int Function(Pointer<Uint8>, int) _randBytes;

  late final Pointer<EvpMdCtx> _mdCtx;
  late final Pointer<EvpCipherCtx> _cipherCtx;
  late final Pointer<Uint8> _digestBuf;
  late final Pointer<Uint32> _digestLen;
  late final Pointer<Int32> _outLen1, _outLen2;
  late final Pointer<Uint8> _keyBuf, _ivBuf;

  Pointer<Uint8> _inBuf = nullptr;
  Pointer<Uint8> _outBuf = nullptr;
  int _allocSize = 0;

  void _ensureBufs(int size) {
    if (size <= _allocSize) return;
    if (_allocSize > 0) {
      malloc.free(_inBuf);
      malloc.free(_outBuf);
    }
    _inBuf = malloc.allocate<Uint8>(size);
    _outBuf = malloc.allocate<Uint8>(size + 64);
    _allocSize = size;
  }

  OpenSslCrypto(String libPath) {
    final lib = DynamicLibrary.open(libPath);

    _mdCtxNew = lib.lookupFunction<_MdCtxNewN, Pointer<EvpMdCtx> Function()>(
        'EVP_MD_CTX_new');
    _mdCtxFree =
        lib.lookupFunction<_MdCtxFreeN, void Function(Pointer<EvpMdCtx>)>(
            'EVP_MD_CTX_free');
    _sha256fn =
        lib.lookupFunction<_Sha256N, Pointer<EvpMd> Function()>('EVP_sha256');
    _digestInitEx = lib.lookupFunction<
        _DigestInitExN,
        int Function(Pointer<EvpMdCtx>, Pointer<EvpMd>,
            Pointer<Void>)>('EVP_DigestInit_ex');
    _digestUpdate = lib.lookupFunction<
        _DigestUpdateN,
        int Function(
            Pointer<EvpMdCtx>, Pointer<Uint8>, int)>('EVP_DigestUpdate');
    _digestFinalEx = lib.lookupFunction<
        _DigestFinalExN,
        int Function(Pointer<EvpMdCtx>, Pointer<Uint8>,
            Pointer<Uint32>)>('EVP_DigestFinal_ex');
    _cipherCtxNew =
        lib.lookupFunction<_CipherCtxNewN, Pointer<EvpCipherCtx> Function()>(
            'EVP_CIPHER_CTX_new');
    _cipherCtxFree = lib.lookupFunction<_CipherCtxFreeN,
        void Function(Pointer<EvpCipherCtx>)>('EVP_CIPHER_CTX_free');
    _aes256Ctr = lib.lookupFunction<_CipherN, Pointer<EvpCipher> Function()>(
        'EVP_aes_256_ctr');
    _chacha20fn = lib.lookupFunction<_CipherN, Pointer<EvpCipher> Function()>(
        'EVP_chacha20');
    _encInitEx = lib.lookupFunction<
        _EncInitExN,
        int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>,
            Pointer<Uint8>, Pointer<Uint8>)>('EVP_EncryptInit_ex');
    _encUpdate = lib.lookupFunction<
        _EncUpdateN,
        int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>,
            Pointer<Uint8>, int)>('EVP_EncryptUpdate');
    _encFinalEx = lib.lookupFunction<
        _EncFinalExN,
        int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>,
            Pointer<Int32>)>('EVP_EncryptFinal_ex');
    _decInitEx = lib.lookupFunction<
        _EncInitExN,
        int Function(Pointer<EvpCipherCtx>, Pointer<EvpCipher>, Pointer<Void>,
            Pointer<Uint8>, Pointer<Uint8>)>('EVP_DecryptInit_ex');
    _decUpdate = lib.lookupFunction<
        _EncUpdateN,
        int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>, Pointer<Int32>,
            Pointer<Uint8>, int)>('EVP_DecryptUpdate');
    _decFinalEx = lib.lookupFunction<
        _EncFinalExN,
        int Function(Pointer<EvpCipherCtx>, Pointer<Uint8>,
            Pointer<Int32>)>('EVP_DecryptFinal_ex');
    _randBytes =
        lib.lookupFunction<_RandBytesN, int Function(Pointer<Uint8>, int)>(
            'RAND_bytes');

    _mdCtx = _mdCtxNew();
    _cipherCtx = _cipherCtxNew();
    _digestBuf = malloc.allocate<Uint8>(32);
    _digestLen = malloc.allocate<Uint32>(1);
    _outLen1 = malloc.allocate<Int32>(1);
    _outLen2 = malloc.allocate<Int32>(1);
    _keyBuf = malloc.allocate<Uint8>(64);
    _ivBuf = malloc.allocate<Uint8>(32);
  }

  Uint8List sha256(Uint8List data) {
    _ensureBufs(data.length);
    _inBuf.asTypedList(data.length).setRange(0, data.length, data);
    _digestInitEx(_mdCtx, _sha256fn(), nullptr);
    _digestUpdate(_mdCtx, _inBuf, data.length);
    _digestFinalEx(_mdCtx, _digestBuf, _digestLen);
    return Uint8List.fromList(_digestBuf.asTypedList(32));
  }

  Uint8List aes256CtrEncrypt(Uint8List p, Uint8List key, Uint8List iv) =>
      _cipher(_aes256Ctr, p, key, iv, enc: true);
  Uint8List aes256CtrDecrypt(Uint8List c, Uint8List key, Uint8List iv) =>
      _cipher(_aes256Ctr, c, key, iv, enc: false);
  Uint8List chacha20Encrypt(Uint8List p, Uint8List key, Uint8List iv) =>
      _cipher(_chacha20fn, p, key, iv, enc: true);
  Uint8List chacha20Decrypt(Uint8List c, Uint8List key, Uint8List iv) =>
      _cipher(_chacha20fn, c, key, iv, enc: false);

  Uint8List randBytes(int n) {
    _ensureBufs(n);
    final rc = _randBytes(_outBuf, n);
    if (rc != 1) throw StateError('RAND_bytes failed (rc=$rc)');
    return Uint8List.fromList(_outBuf.asTypedList(n));
  }

  Uint8List _cipher(Pointer<EvpCipher> Function() fn, Uint8List input,
      Uint8List key, Uint8List iv,
      {required bool enc}) {
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
    return Uint8List.fromList(
        _outBuf.asTypedList(_outLen1.value + _outLen2.value));
  }

  void prewarm(int size) => _ensureBufs(size);

  void dispose() {
    _mdCtxFree(_mdCtx);
    _cipherCtxFree(_cipherCtx);
    for (final p in [_digestBuf, _keyBuf, _ivBuf]) malloc.free(p);
    malloc.free(_digestLen);
    malloc.free(_outLen1);
    malloc.free(_outLen2);
    if (_allocSize > 0) {
      malloc.free(_inBuf);
      malloc.free(_outBuf);
    }
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

Future<void> main(List<String> args) async {
  // Parse: <size_mb> <repeat> [--threads N]
  int threads = 1;
  final positional = <String>[];
  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--threads' || args[i] == '-j') {
      if (i + 1 >= args.length) {
        stderr.writeln('--threads requires a value');
        exit(1);
      }
      threads = int.parse(args[++i]);
    } else {
      positional.add(args[i]);
    }
  }
  if (positional.length != 2) {
    print('Usage: opensslbench <size_mb> <repeat> [--threads N]');
    exit(1);
  }
  if (threads < 1) threads = 1;
  final mBytes = int.parse(positional[0]) * 1024 * 1024;
  final repeat = int.parse(positional[1]);
  final input = _randomBytes(mBytes);

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
  results
      .add(_bench('SHA-256', input, repeat, warmups, () => ffi.sha256(input)));

  // AES-256-CTR
  final aesKey = _randomBytes(32);
  final aesIv = _randomBytes(16);
  _section('AES-256-CTR  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_benchRt('AES-256-CTR', input, repeat, warmups, () {
    final enc = ffi.aes256CtrEncrypt(input, aesKey, aesIv);
    return ffi.aes256CtrDecrypt(enc, aesKey, aesIv);
  }));

  // ChaCha20
  final chaKey = _randomBytes(32);
  final chaIv = _randomBytes(16);
  _section('ChaCha20  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_benchRt('ChaCha20', input, repeat, warmups, () {
    final enc = ffi.chacha20Encrypt(input, chaKey, chaIv);
    return ffi.chacha20Decrypt(enc, chaKey, chaIv);
  }));

  // RAND_bytes
  _section('RAND_bytes (HW RNG)  —  ${mBytes ~/ 1024} KB × $repeat');
  results.add(_bench(
      'RAND_bytes', input, repeat, warmups, () => ffi.randBytes(mBytes)));

  ffi.dispose();
  _printSummary(results, mBytes, repeat);

  // ── Concurrent throughput ──────────────────────────────────────────────
  if (threads > 1) {
    // Build single-threaded mbps baseline from results above
    int _singleMbps(String name) => results
        .firstWhere((r) => r.name == name, orElse: () => _Result(name, 0, 0))
        .mbps;

    // algo label -> (internal key, result name)
    final algos = [
      ('aes256ctr', 'AES-256-CTR'),
      ('chacha20', 'ChaCha20'),
      ('sha256', 'SHA-256'),
    ];

    // Use enough reps that crypto time >> isolate spawn time (~200 ms each).
    // Target: ~2 s of crypto work per isolate.
    // Exclude RAND_bytes (HW RNG is 10-100× faster and skews the count).
    final cipherMbps = results
        .where((r) => r.name != 'RAND_bytes')
        .map((r) => r.mbps)
        .fold<int>(1, max);
    // enc+dec per rep = 2 × mBytes; cipherMbps/8 = MB/s
    final targetReps =
        max(10, (2.0 * cipherMbps * 1e6 / 8 / (mBytes * 2)).ceil());
    final concRepeat = max(repeat * 3, targetReps);

    print('');
    print(chalk.cyan(
        '── CONCURRENT THROUGHPUT  ($threads isolates × ${mBytes ~/ (1024 * 1024)} MB × $concRepeat reps)'));
    print(chalk.yellow(
        '  Each isolate generates its own data/key/IV and runs independently.'));
    print(chalk.yellow(
        '  Throughput = total bytes / slowest-isolate wall time (spawn overhead excluded).'));
    if (Platform.isMacOS || Platform.isLinux)
      print(chalk.yellow(
          '  AES-NI is per-core; expect near-linear scaling up to physical core count.'));

    final concRows = <({String algo, int threads, int mbps, int singleMbps})>[];
    for (final (key, label) in algos) {
      stdout.write('  $label ... ');
      final r =
          await _runConcurrentCipher(path, key, mBytes, concRepeat, threads);
      // Aggregate Mbps: total bits / slowest-isolate seconds
      final mbps = r.wallUs == 0
          ? 0
          : ((r.totalBytes * 8 / 1e6) / (r.wallUs / 1e6)).round();
      stdout.writeln(r.ok ? chalk.green('$mbps Mbps') : chalk.red('ERROR'));
      concRows.add((
        algo: label,
        threads: threads,
        mbps: mbps,
        singleMbps: _singleMbps(label)
      ));
    }

    _printConcurrentSummary(concRows, mBytes, concRepeat);
  }
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

_Result _bench(
    String name, Uint8List input, int repeat, int warmups, void Function() fn) {
  for (var i = 0; i < warmups; i++) fn();
  final sw = Stopwatch()..start();
  for (var i = 0; i < repeat; i++) {
    fn();
    stdout.write('.');
  }
  sw.stop();
  return _finish(name, input, repeat, sw.elapsedMilliseconds);
}

_Result _benchRt(String name, Uint8List input, int repeat, int warmups,
    Uint8List Function() fn) {
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
  final mbps =
      ms == 0 ? 0 : (((input.length * 8 * repeat) / 1e6) / (ms / 1000)).round();
  print('  ${chalk.green('$mbps mbps')}  ($ms ms)');
  return _Result(name, mbps, ms);
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

void _printSummary(List<_Result> results, int mBytes, int repeat) {
  print('');
  print(chalk.blue('=' * 60));
  print(chalk.blue(
      'OPENSSL FFI BENCHMARK — ${Platform.operatingSystem.toUpperCase()}'));
  print(chalk.blue('=' * 60));
  print('  Data: ${mBytes ~/ (1024 * 1024)} MB   Iterations: $repeat');
  print('');
  print('┌──────────────────┬─────────────┬───────────────┐');
  print('│ Algorithm        │   Time (ms) │  Speed (mbps) │');
  print('├──────────────────┼─────────────┼───────────────┤');
  for (final r in results) {
    print(
        '│ ${r.name.padRight(16)} │ ${r.ms.toString().padLeft(11)} │ ${r.mbps.toString().padLeft(13)} │');
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
        (l) => l.startsWith('flags') || l.startsWith('Features'),
        orElse: () => '');
    final flags = line.split(':').last.trim().split(' ').toSet();
    final hw = ['aes', 'sha_ni', 'avx2', 'avx512f', 'neon']
        .where(flags.contains)
        .toList();
    print(chalk.cyan(hw.isEmpty
        ? 'CPU: no hw-accel flags detected'
        : 'CPU hw-accel : ${hw.join(', ')}'));
  } catch (_) {}
}

String _installHint() {
  if (Platform.isLinux)
    return 'Install: sudo apt-get install libssl-dev  (or equivalent)';
  if (Platform.isMacOS) return 'Install: brew install openssl@3';
  if (Platform.isWindows)
    return 'Download Win64 OpenSSL from https://slproweb.com/products/Win32OpenSSL.html';
  return 'Install OpenSSL for your platform.';
}

Uint8List _randomBytes(int n) {
  final rng = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
}

class _Result {
  final String name;
  final int mbps;
  final int ms;
  _Result(this.name, this.mbps, this.ms);
}

// ---------------------------------------------------------------------------
// Isolate-based concurrent throughput benchmark
// ---------------------------------------------------------------------------

/// Sendable args for each cipher worker isolate.
class _CipherIsolateArgs {
  final SendPort sendPort;
  final String libPath;
  final String algo; // 'aes256ctr' | 'chacha20' | 'sha256'
  final int sizeBytes;
  final int repeat;
  const _CipherIsolateArgs(
      this.sendPort, this.libPath, this.algo, this.sizeBytes, this.repeat);
}

/// Result sent back from each worker isolate.
class _CipherIsolateResult {
  final String algo;
  final int totalBytes; // bytes processed (enc + dec each count once)
  final int wallUs;
  final bool ok;
  const _CipherIsolateResult(this.algo, this.totalBytes, this.wallUs, this.ok);
}

/// Worker entry point — runs in its own OS thread via Dart isolate.
/// Generates its own data/key/IV locally to avoid large inter-isolate copies.
void _cipherIsolateWorker(_CipherIsolateArgs args) {
  final crypto = OpenSslCrypto(args.libPath);
  // Each isolate uses its own local random data — avoids copying across isolates
  // and ensures the benchmark reflects pure crypto throughput.
  final rng = Random.secure();
  final data = Uint8List.fromList(
      List.generate(args.sizeBytes, (_) => rng.nextInt(256)));
  final key = Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));
  final iv = Uint8List.fromList(List.generate(16, (_) => rng.nextInt(256)));

  crypto.prewarm(args.sizeBytes);

  int totalBytes = 0;
  bool ok = true;
  final sw = Stopwatch()..start();

  switch (args.algo) {
    case 'aes256ctr':
      for (var i = 0; i < args.repeat; i++) {
        final enc = crypto.aes256CtrEncrypt(data, key, iv);
        crypto.aes256CtrDecrypt(enc, key, iv);
        totalBytes += data.length * 2; // enc + dec
      }
    case 'chacha20':
      for (var i = 0; i < args.repeat; i++) {
        final enc = crypto.chacha20Encrypt(data, key, iv);
        crypto.chacha20Decrypt(enc, key, iv);
        totalBytes += data.length * 2;
      }
    case 'sha256':
      for (var i = 0; i < args.repeat; i++) {
        crypto.sha256(data);
        totalBytes += data.length;
      }
    default:
      ok = false;
  }

  sw.stop();
  crypto.dispose();
  args.sendPort.send(
      _CipherIsolateResult(args.algo, totalBytes, sw.elapsedMicroseconds, ok));
}

/// Spawn [threads] concurrent isolates and collect their throughput results.
/// Uses max(per-isolate wallUs) as the denominator so Dart isolate spawn
/// overhead does not pollute the throughput measurement.
Future<({int totalBytes, int wallUs, bool ok})> _runConcurrentCipher(
    String libPath, String algo, int sizeBytes, int repeat, int threads) async {
  final receivePort = ReceivePort();
  final results = <_CipherIsolateResult>[];
  final completer = Completer<void>();
  int received = 0;

  receivePort.listen((msg) {
    if (msg is _CipherIsolateResult) {
      results.add(msg);
      received++;
      if (received == threads) completer.complete();
    }
  });

  for (var i = 0; i < threads; i++) {
    await Isolate.spawn(
        _cipherIsolateWorker,
        _CipherIsolateArgs(
            receivePort.sendPort, libPath, algo, sizeBytes, repeat));
  }

  await completer.future;
  receivePort.close();

  final totalBytes = results.fold<int>(0, (s, r) => s + r.totalBytes);
  // Use the slowest isolate's own wall time (excludes spawn overhead)
  // to measure true sustained parallel throughput.
  final maxWallUs = results.fold<int>(0, (m, r) => r.wallUs > m ? r.wallUs : m);
  final ok = results.every((r) => r.ok);
  return (totalBytes: totalBytes, wallUs: maxWallUs, ok: ok);
}

// ---------------------------------------------------------------------------
// Concurrent summary printer
// ---------------------------------------------------------------------------

void _printConcurrentSummary(
    List<({String algo, int threads, int mbps, int singleMbps})> rows,
    int sizeBytes,
    int repeat) {
  print('');
  print(chalk.blue('=' * 72));
  print(chalk.blue(
      'CONCURRENT THROUGHPUT — ${Platform.operatingSystem.toUpperCase()}'));
  print(chalk.blue('=' * 72));
  print(chalk.yellow(
      'Each isolate = OS thread. FFI calls run outside the Dart event loop.'));
  print(chalk.yellow(
      'Data: ${sizeBytes ~/ (1024 * 1024)} MB/isolate × $repeat reps  (enc+dec = 2× bytes counted)'));
  print('');
  print(
      '┌──────────────────┬──────────┬──────────────┬──────────────┬──────────┐');
  print(
      '│ Algorithm        │ Threads  │ Aggr. Mbps   │ Single Mbps  │ Scaling  │');
  print(
      '├──────────────────┼──────────┼──────────────┼──────────────┼──────────┤');
  for (final r in rows) {
    final scaling =
        r.singleMbps > 0 ? (r.mbps / r.singleMbps).toStringAsFixed(2) : '-';
    print('│ ${r.algo.padRight(16)} │ ${r.threads.toString().padLeft(8)} │ '
        '${r.mbps.toString().padLeft(12)} │ '
        '${r.singleMbps.toString().padLeft(12)} │ '
        '${('${scaling}×').padLeft(8)} │');
  }
  print(
      '└──────────────────┴──────────┴──────────────┴──────────────┴──────────┘');
  print(chalk.yellow(
      'Scaling > N means HW-AES pipelines across cores; < 1.0 indicates lock contention.'));
  print(chalk.blue('=' * 72));
}
