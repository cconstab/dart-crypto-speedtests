/// Standalone OpenSSL benchmark.
///
/// Compares three implementations of the same algorithms:
///   FFI   — system libcrypto loaded at runtime, hardware-accelerated (AES-NI / SHA-NI)
///   naive — openssl pub package, Arena-per-call, OpenSSL compiled with no-asm (no hw-accel)
///   opt   — openssl pub package, persistent EVP contexts, same no-asm binary
///
/// Build:   dart build cli -t bin/opensslbench.dart
/// Run:     ./build/cli/linux_x64/bundle/bin/opensslbench <MB> <repeat>

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:boring/boring.dart';
import 'package:chalk/chalk.dart';
import 'package:collection/collection.dart';

// ---------------------------------------------------------------------------

void main(List<String> args) {
  if (args.length != 2) {
    print('opensslbench <size_mb> <repeat>');
    exit(1);
  }
  final mBytes = int.parse(args[0]) * 1024 * 1024;
  final repeat = int.parse(args[1]);
  final input  = _randomBytes(mBytes);

  _printCpuFeatures();

  OpenSslCrypto? ffi;
  try {
    ffi = OpenSslCrypto(getOpenSslLibPath());
    ffi.prewarm(input.length);
    print('FFI     : ${getOpenSslLibPath()}');
  } catch (e) {
    print(chalk.yellow('FFI OpenSSL unavailable: $e'));
  }

  OpenSslPkgCrypto? pkg;
  try {
    pkg = OpenSslPkgCrypto();
    pkg.prewarm(input.length);
    print('Pkg     : bundled OpenSSL (no-asm, no hw-accel)');
  } catch (e) {
    print(chalk.yellow('OpenSSL pkg unavailable: $e'));
  }

  final results = <_Result>[];

  _section('SHA-256  —  ${input.length ~/ 1024} KB × $repeat');
  results.addAll(_benchSha256(input, repeat, ffi: ffi, pkg: pkg));

  _section('AES-256-CTR  —  ${input.length ~/ 1024} KB × $repeat');
  results.addAll(_benchAesCtr(input, repeat, ffi: ffi, pkg: pkg));

  _section('ChaCha20  —  ${input.length ~/ 1024} KB × $repeat');
  results.addAll(_benchChacha20(input, repeat, ffi: ffi, pkg: pkg));

  _section('RAND_bytes (HW RNG)  —  ${input.length ~/ 1024} KB × $repeat');
  results.addAll(_benchRand(input, repeat, ffi: ffi));

  ffi?.dispose();
  pkg?.dispose();

  _printSummary(results, mBytes, repeat);
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

List<_Result> _benchSha256(
  Uint8List input,
  int repeat, {
  OpenSslCrypto?    ffi,
  OpenSslPkgCrypto? pkg,
}) {
  final results = <_Result>[];

  if (ffi != null) {
    results.add(_time('FFI  SHA-256 (hw-accel)', input, repeat, () {
      ffi.sha256(input);
    }));
  }
  if (pkg != null) {
    results.add(_time('Pkg  SHA-256 naive      ', input, repeat, () {
      opensslPkgSha256(input);
    }));
    results.add(_time('Pkg  SHA-256 opt        ', input, repeat, () {
      pkg.sha256(input);
    }));
  }

  return results;
}

List<_Result> _benchAesCtr(
  Uint8List input,
  int repeat, {
  OpenSslCrypto?    ffi,
  OpenSslPkgCrypto? pkg,
}) {
  final results = <_Result>[];
  final key = _randomBytes(32);
  final iv  = _randomBytes(16);

  if (ffi != null) {
    results.add(_timeRoundtrip('FFI  AES-256-CTR (hw-accel)', input, repeat, () {
      final enc = ffi.aes256CtrEncrypt(input, key, iv);
      return ffi.aes256CtrDecrypt(enc, key, iv);
    }));
  }
  if (pkg != null) {
    results.add(_timeRoundtrip('Pkg  AES-256-CTR naive      ', input, repeat, () {
      final enc = opensslPkgAes256CtrEncrypt(input, key, iv);
      return opensslPkgAes256CtrDecrypt(enc, key, iv);
    }));
    results.add(_timeRoundtrip('Pkg  AES-256-CTR opt        ', input, repeat, () {
      final enc = pkg.aes256CtrEncrypt(input, key, iv);
      return pkg.aes256CtrDecrypt(enc, key, iv);
    }));
  }

  return results;
}

List<_Result> _benchChacha20(
  Uint8List input,
  int repeat, {
  OpenSslCrypto?    ffi,
  OpenSslPkgCrypto? pkg,
}) {
  final results = <_Result>[];
  final key = _randomBytes(32);
  final iv  = _randomBytes(16); // 4-byte counter + 12-byte nonce

  if (ffi != null) {
    results.add(_timeRoundtrip('FFI  ChaCha20 (hw-accel)', input, repeat, () {
      final enc = ffi.chacha20Encrypt(input, key, iv);
      return ffi.chacha20Decrypt(enc, key, iv);
    }));
  }
  if (pkg != null) {
    results.add(_timeRoundtrip('Pkg  ChaCha20 naive      ', input, repeat, () {
      final enc = opensslPkgChacha20Encrypt(input, key, iv);
      return opensslPkgChacha20Decrypt(enc, key, iv);
    }));
    results.add(_timeRoundtrip('Pkg  ChaCha20 opt        ', input, repeat, () {
      final enc = pkg.chacha20Encrypt(input, key, iv);
      return pkg.chacha20Decrypt(enc, key, iv);
    }));
  }

  return results;
}

List<_Result> _benchRand(
  Uint8List input,
  int repeat, {
  OpenSslCrypto? ffi,
}) {
  final results = <_Result>[];
  final n = input.length;

  if (ffi != null) {
    results.add(_time('FFI  RAND_bytes (hw-accel)', input, repeat, () {
      ffi.randBytes(n);
    }));
  }

  return results;
}

// ---------------------------------------------------------------------------
// Timing primitives
// ---------------------------------------------------------------------------

_Result _time(String name, Uint8List input, int repeat, void Function() fn) {
  final warmups = min(2, repeat);
  for (var i = 0; i < warmups; i++) fn();

  final sw = Stopwatch()..start();
  for (var i = 0; i < repeat; i++) {
    fn();
    stdout.write('.');
  }
  sw.stop();

  final ms   = sw.elapsedMilliseconds;
  final mbps = _mbps(input.length, repeat, ms);
  print('  ${chalk.green('$mbps mbps')}  ($ms ms)');
  return _Result(name, mbps, ms);
}

_Result _timeRoundtrip(
  String name,
  Uint8List input,
  int repeat,
  Uint8List Function() fn,
) {
  final warmups = min(2, repeat);
  for (var i = 0; i < warmups; i++) fn();

  final sw = Stopwatch()..start();
  bool ok = true;
  for (var i = 0; i < repeat; i++) {
    final result = fn();
    if (!const ListEquality<int>().equals(result, input)) ok = false;
    stdout.write(ok ? '.' : chalk.red('!'));
  }
  sw.stop();

  final ms   = sw.elapsedMilliseconds;
  final mbps = _mbps(input.length, repeat, ms);
  print('  ${chalk.green('$mbps mbps')}  ($ms ms)${ok ? '' : chalk.red('  MISMATCH')}');
  return _Result(name, mbps, ms);
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

void _printSummary(List<_Result> results, int mBytes, int repeat) {
  print('');
  print(chalk.blue('=' * 72));
  print(chalk.blue('OPENSSL BENCHMARK SUMMARY'));
  print(chalk.blue('=' * 72));
  print('  Data: ${mBytes ~/ (1024 * 1024)} MB   Iterations: $repeat');
  print('');
  print('┌──────────────────────────────────┬─────────────┬───────────────┐');
  print('│ Implementation                   │   Time (ms) │  Speed (mbps) │');
  print('├──────────────────────────────────┼─────────────┼───────────────┤');

  String? lastAlgo;
  for (final r in results) {
    final algo = r.name.contains('SHA-256') ? 'SHA-256'
               : r.name.contains('AES')     ? 'AES-256-CTR'
               :                              'ChaCha20';
    if (algo != lastAlgo) {
      if (lastAlgo != null) {
        print('├──────────────────────────────────┼─────────────┼───────────────┤');
      }
      lastAlgo = algo;
    }
    final label = r.name.trimRight().padRight(32);
    print('│ $label │ ${r.ms.toString().padLeft(11)} │ ${r.mbps.toString().padLeft(13)} │');
  }
  print('└──────────────────────────────────┴─────────────┴───────────────┘');

  // Per-algo winner
  print('');
  for (final algo in ['SHA-256', 'AES-256-CTR', 'ChaCha20']) {
    final group = results.where((r) => r.name.contains(
        algo == 'SHA-256' ? 'SHA-256' : algo == 'AES-256-CTR' ? 'AES' : 'ChaCha20'
    )).toList();
    if (group.isEmpty) continue;
    final best = group.reduce((a, b) => a.mbps > b.mbps ? a : b);
    final worst = group.reduce((a, b) => a.mbps < b.mbps ? a : b);
    final ratio = (best.mbps / worst.mbps).toStringAsFixed(1);
    print('${chalk.green('  $algo')}  best: ${best.name.trim()} @ ${best.mbps} mbps'
          '  (${ratio}× faster than slowest)');
  }
  print(chalk.blue('=' * 72));
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

void _section(String title) {
  print('');
  print(chalk.cyan('── $title'));
}

void _printCpuFeatures() {
  if (!Platform.isLinux) return;
  try {
    final cpuinfo = File('/proc/cpuinfo').readAsStringSync();
    final flagsLine = cpuinfo.split('\n').firstWhere(
      (l) => l.startsWith('flags') || l.startsWith('Features'),
      orElse: () => '',
    );
    final flags = flagsLine.split(':').last.trim().split(' ').toSet();
    final interesting = ['aes', 'sha_ni', 'avx2', 'avx512f', 'neon'];
    final found = interesting.where(flags.contains).toList();
    print(chalk.cyan(found.isEmpty
        ? 'CPU: no detected hw-accel flags (aes/sha_ni/avx2/neon)'
        : 'CPU hw-accel : ${found.join(', ')}'));
  } catch (_) {}
}

int _mbps(int bytes, int repeat, int ms) =>
    ms == 0 ? 0 : (((bytes * 8 * repeat) / 1e6) / (ms / 1000)).round();

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
