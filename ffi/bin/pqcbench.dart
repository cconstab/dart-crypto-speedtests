/// Post-Quantum Cryptography benchmark using OpenSSL 3.5+ native PQC.
///
/// Tests ML-KEM (key encapsulation), ML-DSA and SLH-DSA (signatures).
/// Requires OpenSSL 3.5.0+ — gracefully skips unavailable algorithms.
///
/// Build:  dart compile exe bin/pqcbench.dart -o pqcbench
/// Run:    ./pqcbench [iterations] [--threads N]
///         Default iterations: 100 for KEM/ML-DSA, 10 for SLH-DSA (slow sign)
///         --threads N: run concurrent throughput benchmark with N isolates
///                      (each isolate = true OS thread via FFI native calls)
///
/// Supported platforms: Linux x86_64/aarch64, macOS, Windows.

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:chalk/chalk.dart';
import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// Opaque EVP_PKEY types
// ---------------------------------------------------------------------------

final class EvpPkey extends Opaque {}

final class EvpPkeyCtx extends Opaque {}

final class EvpMdCtx extends Opaque {}

final class OsslLibCtx extends Opaque {}

// ---------------------------------------------------------------------------
// Native typedefs
// ---------------------------------------------------------------------------

// EVP_PKEY_CTX lifecycle
typedef _PkeyCtxNewFromNameN = Pointer<EvpPkeyCtx> Function(
    Pointer<OsslLibCtx>, Pointer<Uint8>, Pointer<Void>);
typedef _PkeyCtxFreeN = Void Function(Pointer<EvpPkeyCtx>);
typedef _PkeyFreeN = Void Function(Pointer<EvpPkey>);
typedef _PkeyCtxIntN = Int32 Function(Pointer<EvpPkeyCtx>);

// keygen
typedef _KeygenN = Int32 Function(
    Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>);

// KEM encapsulate / decapsulate
typedef _EncapInitN = Int32 Function(Pointer<EvpPkeyCtx>,
    Pointer<Void>); // EVP_PKEY_encapsulate_init(ctx, params)
typedef _EncapN = Int32 Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>,
    Pointer<Size>, Pointer<Uint8>, Pointer<Size>);
typedef _DecapInitN = Int32 Function(Pointer<EvpPkeyCtx>, Pointer<Void>);
typedef _DecapN = Int32 Function(
    Pointer<EvpPkeyCtx>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, Size);

// EVP_PKEY_CTX_new_from_pkey (for encap/decap using existing key)
typedef _PkeyCtxNewFromPkeyN = Pointer<EvpPkeyCtx> Function(
    Pointer<OsslLibCtx>, Pointer<EvpPkey>, Pointer<Void>);

// DigestSign / DigestVerify (one-shot)
typedef _MdCtxNewN = Pointer<EvpMdCtx> Function();
typedef _MdCtxFreeN = Void Function(Pointer<EvpMdCtx>);
typedef _DigestSignInitExN = Int32 Function(
    Pointer<EvpMdCtx>,
    Pointer<Pointer<EvpPkeyCtx>>,
    Pointer<Uint8>,
    Pointer<OsslLibCtx>,
    Pointer<Uint8>,
    Pointer<EvpPkey>,
    Pointer<Void>);
typedef _DigestSignN = Int32 Function(
    Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, Size);
typedef _DigestVerifyInitExN = Int32 Function(
    Pointer<EvpMdCtx>,
    Pointer<Pointer<EvpPkeyCtx>>,
    Pointer<Uint8>,
    Pointer<OsslLibCtx>,
    Pointer<Uint8>,
    Pointer<EvpPkey>,
    Pointer<Void>);
typedef _DigestVerifyN = Int32 Function(
    Pointer<EvpMdCtx>, Pointer<Uint8>, Size, Pointer<Uint8>, Size);

// Error string
typedef _ErrReasonErrorStringN = Pointer<Uint8> Function(IntPtr);

// ---------------------------------------------------------------------------
// PqcBench — wraps EVP_PKEY operations for PQC algorithms
// ---------------------------------------------------------------------------

class PqcBench {
  late final Pointer<EvpPkeyCtx> Function(
      Pointer<OsslLibCtx>, Pointer<Uint8>, Pointer<Void>) _pkeyCtxNewFromName;
  late final Pointer<EvpPkeyCtx> Function(
      Pointer<OsslLibCtx>, Pointer<EvpPkey>, Pointer<Void>) _pkeyCtxNewFromPkey;
  late final void Function(Pointer<EvpPkeyCtx>) _pkeyCtxFree;
  late final void Function(Pointer<EvpPkey>) _pkeyFree;
  late final int Function(Pointer<EvpPkeyCtx>) _keygenInit;
  late final int Function(Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>)
      _keygen;
  late final int Function(Pointer<EvpPkeyCtx>, Pointer<Void>) _kemEncapInit;
  late final int Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>, Pointer<Size>,
      Pointer<Uint8>, Pointer<Size>) _encap;
  late final int Function(Pointer<EvpPkeyCtx>, Pointer<Void>) _kemDecapInit;
  late final int Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>, Pointer<Size>,
      Pointer<Uint8>, int) _decap;
  late final Pointer<EvpMdCtx> Function() _mdCtxNew;
  late final void Function(Pointer<EvpMdCtx>) _mdCtxFree;
  late final int Function(
      Pointer<EvpMdCtx>,
      Pointer<Pointer<EvpPkeyCtx>>,
      Pointer<Uint8>,
      Pointer<OsslLibCtx>,
      Pointer<Uint8>,
      Pointer<EvpPkey>,
      Pointer<Void>) _digestSignInitEx;
  late final int Function(
          Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, int)
      _digestSign;
  late final int Function(
      Pointer<EvpMdCtx>,
      Pointer<Pointer<EvpPkeyCtx>>,
      Pointer<Uint8>,
      Pointer<OsslLibCtx>,
      Pointer<Uint8>,
      Pointer<EvpPkey>,
      Pointer<Void>) _digestVerifyInitEx;
  late final int Function(
          Pointer<EvpMdCtx>, Pointer<Uint8>, int, Pointer<Uint8>, int)
      _digestVerify;
  late final Pointer<Uint8> Function(int) _errReasonStr;

  PqcBench(String libPath) {
    final lib = DynamicLibrary.open(libPath);

    _pkeyCtxNewFromName = lib.lookupFunction<
        _PkeyCtxNewFromNameN,
        Pointer<EvpPkeyCtx> Function(Pointer<OsslLibCtx>, Pointer<Uint8>,
            Pointer<Void>)>('EVP_PKEY_CTX_new_from_name');
    _pkeyCtxNewFromPkey = lib.lookupFunction<
        _PkeyCtxNewFromPkeyN,
        Pointer<EvpPkeyCtx> Function(Pointer<OsslLibCtx>, Pointer<EvpPkey>,
            Pointer<Void>)>('EVP_PKEY_CTX_new_from_pkey');
    _pkeyCtxFree =
        lib.lookupFunction<_PkeyCtxFreeN, void Function(Pointer<EvpPkeyCtx>)>(
            'EVP_PKEY_CTX_free');
    _pkeyFree = lib.lookupFunction<_PkeyFreeN, void Function(Pointer<EvpPkey>)>(
        'EVP_PKEY_free');
    _keygenInit =
        lib.lookupFunction<_PkeyCtxIntN, int Function(Pointer<EvpPkeyCtx>)>(
            'EVP_PKEY_keygen_init');
    _keygen = lib.lookupFunction<
        _KeygenN,
        int Function(
            Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>)>('EVP_PKEY_keygen');
    _kemEncapInit = lib.lookupFunction<
        _EncapInitN,
        int Function(
            Pointer<EvpPkeyCtx>, Pointer<Void>)>('EVP_PKEY_encapsulate_init');
    _encap = lib.lookupFunction<
        _EncapN,
        int Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>, Pointer<Size>,
            Pointer<Uint8>, Pointer<Size>)>('EVP_PKEY_encapsulate');
    _kemDecapInit = lib.lookupFunction<
        _DecapInitN,
        int Function(
            Pointer<EvpPkeyCtx>, Pointer<Void>)>('EVP_PKEY_decapsulate_init');
    _decap = lib.lookupFunction<
        _DecapN,
        int Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>, Pointer<Size>,
            Pointer<Uint8>, int)>('EVP_PKEY_decapsulate');
    _mdCtxNew = lib.lookupFunction<_MdCtxNewN, Pointer<EvpMdCtx> Function()>(
        'EVP_MD_CTX_new');
    _mdCtxFree =
        lib.lookupFunction<_MdCtxFreeN, void Function(Pointer<EvpMdCtx>)>(
            'EVP_MD_CTX_free');
    _digestSignInitEx = lib.lookupFunction<
        _DigestSignInitExN,
        int Function(
            Pointer<EvpMdCtx>,
            Pointer<Pointer<EvpPkeyCtx>>,
            Pointer<Uint8>,
            Pointer<OsslLibCtx>,
            Pointer<Uint8>,
            Pointer<EvpPkey>,
            Pointer<Void>)>('EVP_DigestSignInit_ex');
    _digestSign = lib.lookupFunction<
        _DigestSignN,
        int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, Pointer<Size>,
            Pointer<Uint8>, int)>('EVP_DigestSign');
    _digestVerifyInitEx = lib.lookupFunction<
        _DigestVerifyInitExN,
        int Function(
            Pointer<EvpMdCtx>,
            Pointer<Pointer<EvpPkeyCtx>>,
            Pointer<Uint8>,
            Pointer<OsslLibCtx>,
            Pointer<Uint8>,
            Pointer<EvpPkey>,
            Pointer<Void>)>('EVP_DigestVerifyInit_ex');
    _digestVerify = lib.lookupFunction<
        _DigestVerifyN,
        int Function(Pointer<EvpMdCtx>, Pointer<Uint8>, int, Pointer<Uint8>,
            int)>('EVP_DigestVerify');
    _errReasonStr = lib.lookupFunction<_ErrReasonErrorStringN,
        Pointer<Uint8> Function(int)>('ERR_reason_error_string');
  }

  /// Returns null if the algorithm is not supported by this OpenSSL build.
  Pointer<EvpPkey>? tryKeygen(String algoName) {
    final nameBytes = algoName.toNativeUtf8().cast<Uint8>();
    final ctx = _pkeyCtxNewFromName(nullptr.cast(), nameBytes, nullptr.cast());
    malloc.free(nameBytes);
    if (ctx == nullptr) return null;
    try {
      if (_keygenInit(ctx) != 1) return null;
      final pkey =
          malloc.allocate<Pointer<EvpPkey>>(sizeOf<Pointer<EvpPkey>>());
      pkey.value = nullptr;
      final rc = _keygen(ctx, pkey);
      if (rc != 1 || pkey.value == nullptr) {
        malloc.free(pkey);
        return null;
      }
      final result = pkey.value;
      malloc.free(pkey);
      return result;
    } finally {
      _pkeyCtxFree(ctx);
    }
  }

  /// KEM: encapsulate using public key, returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Pointer<EvpPkey> pubkey) {
    final ctx = _pkeyCtxNewFromPkey(nullptr.cast(), pubkey, nullptr.cast());
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_pkey failed');
    try {
      if (_kemEncapInit(ctx, nullptr.cast()) != 1)
        throw StateError('EVP_PKEY_encapsulate_init failed');
      // First call: get sizes
      final ctLen = malloc.allocate<Size>(sizeOf<Size>());
      final ssLen = malloc.allocate<Size>(sizeOf<Size>());
      ctLen.value = 0;
      ssLen.value = 0;
      if (_encap(ctx, nullptr, ctLen, nullptr, ssLen) != 1) {
        throw StateError('EVP_PKEY_encapsulate (size query) failed');
      }
      final ct = malloc.allocate<Uint8>(ctLen.value);
      final ss = malloc.allocate<Uint8>(ssLen.value);
      if (_encap(ctx, ct, ctLen, ss, ssLen) != 1) {
        throw StateError('EVP_PKEY_encapsulate failed');
      }
      final ctOut = Uint8List.fromList(ct.asTypedList(ctLen.value));
      final ssOut = Uint8List.fromList(ss.asTypedList(ssLen.value));
      malloc.free(ct);
      malloc.free(ss);
      malloc.free(ctLen);
      malloc.free(ssLen);
      return (ctOut, ssOut);
    } finally {
      _pkeyCtxFree(ctx);
    }
  }

  /// KEM: decapsulate using private key, returns shared secret.
  Uint8List decapsulate(Pointer<EvpPkey> privkey, Uint8List ciphertext) {
    final ctx = _pkeyCtxNewFromPkey(nullptr.cast(), privkey, nullptr.cast());
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_pkey failed');
    try {
      if (_kemDecapInit(ctx, nullptr.cast()) != 1)
        throw StateError('EVP_PKEY_decapsulate_init failed');
      final ctNative = malloc.allocate<Uint8>(ciphertext.length);
      ctNative.asTypedList(ciphertext.length).setAll(0, ciphertext);
      // Size query
      final ssLen = malloc.allocate<Size>(sizeOf<Size>());
      ssLen.value = 0;
      if (_decap(ctx, nullptr, ssLen, ctNative, ciphertext.length) != 1) {
        throw StateError('EVP_PKEY_decapsulate (size query) failed');
      }
      final ss = malloc.allocate<Uint8>(ssLen.value);
      if (_decap(ctx, ss, ssLen, ctNative, ciphertext.length) != 1) {
        throw StateError('EVP_PKEY_decapsulate failed');
      }
      final result = Uint8List.fromList(ss.asTypedList(ssLen.value));
      malloc.free(ss);
      malloc.free(ssLen);
      malloc.free(ctNative);
      return result;
    } finally {
      _pkeyCtxFree(ctx);
    }
  }

  /// Sign message, returns signature bytes.
  Uint8List sign(Pointer<EvpPkey> privkey, Uint8List message) {
    final mdCtx = _mdCtxNew();
    if (mdCtx == nullptr) throw StateError('EVP_MD_CTX_new failed');
    try {
      final msgNative = malloc.allocate<Uint8>(message.length);
      msgNative.asTypedList(message.length).setAll(0, message);
      final pkeyCtxPtr =
          malloc.allocate<Pointer<EvpPkeyCtx>>(sizeOf<Pointer<EvpPkeyCtx>>());
      if (_digestSignInitEx(mdCtx, pkeyCtxPtr, nullptr, nullptr.cast(), nullptr,
              privkey, nullptr.cast()) !=
          1) {
        throw StateError('EVP_DigestSignInit_ex failed');
      }
      // Size query
      final sigLen = malloc.allocate<Size>(sizeOf<Size>());
      sigLen.value = 0;
      if (_digestSign(mdCtx, nullptr, sigLen, msgNative, message.length) != 1) {
        throw StateError('EVP_DigestSign (size query) failed');
      }
      final sig = malloc.allocate<Uint8>(sigLen.value);
      if (_digestSign(mdCtx, sig, sigLen, msgNative, message.length) != 1) {
        throw StateError('EVP_DigestSign failed');
      }
      final result = Uint8List.fromList(sig.asTypedList(sigLen.value));
      malloc.free(sig);
      malloc.free(sigLen);
      malloc.free(msgNative);
      malloc.free(pkeyCtxPtr);
      return result;
    } finally {
      _mdCtxFree(mdCtx);
    }
  }

  /// Verify signature. Returns true if valid.
  bool verify(Pointer<EvpPkey> pubkey, Uint8List message, Uint8List signature) {
    final mdCtx = _mdCtxNew();
    if (mdCtx == nullptr) return false;
    try {
      final msgNative = malloc.allocate<Uint8>(message.length);
      msgNative.asTypedList(message.length).setAll(0, message);
      final sigNative = malloc.allocate<Uint8>(signature.length);
      sigNative.asTypedList(signature.length).setAll(0, signature);
      final pkeyCtxPtr =
          malloc.allocate<Pointer<EvpPkeyCtx>>(sizeOf<Pointer<EvpPkeyCtx>>());
      final rc1 = _digestVerifyInitEx(mdCtx, pkeyCtxPtr, nullptr,
          nullptr.cast(), nullptr, pubkey, nullptr.cast());
      if (rc1 != 1) {
        malloc.free(msgNative);
        malloc.free(sigNative);
        malloc.free(pkeyCtxPtr);
        return false;
      }
      final rc2 = _digestVerify(
          mdCtx, sigNative, signature.length, msgNative, message.length);
      malloc.free(msgNative);
      malloc.free(sigNative);
      malloc.free(pkeyCtxPtr);
      return rc2 == 1;
    } finally {
      _mdCtxFree(mdCtx);
    }
  }

  void freeKey(Pointer<EvpPkey> key) => _pkeyFree(key);
}

// ---------------------------------------------------------------------------
// Platform path resolution (shared with opensslbench)
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
// Result types
// ---------------------------------------------------------------------------

class _KemResult {
  final String name;
  final int keygenUs;
  final int encapUs;
  final int decapUs;
  final int ctBytes;
  final int ssBytes;
  final bool ssMatch;
  _KemResult(this.name, this.keygenUs, this.encapUs, this.decapUs, this.ctBytes,
      this.ssBytes, this.ssMatch);
}

class _SigResult {
  final String name;
  final int keygenUs;
  final int signUs;
  final int verifyUs;
  final int sigBytes;
  final bool verifyOk;
  _SigResult(this.name, this.keygenUs, this.signUs, this.verifyUs,
      this.sigBytes, this.verifyOk);
}

// ---------------------------------------------------------------------------
// Isolate-based concurrent throughput benchmark
// ---------------------------------------------------------------------------

// Message types for isolate communication — must use only sendable types.

class _IsolateArgs {
  final SendPort sendPort;
  final String libPath;
  final String algo;
  final int iters;
  final String type; // 'kem' | 'sig'
  final List<int> message; // for sig
  const _IsolateArgs(
      this.sendPort, this.libPath, this.algo, this.iters, this.type,
      [this.message = const []]);
}

class _IsolateResult {
  final String algo;
  final String type;
  final int iters;
  final int totalUs; // wall-clock µs this isolate spent
  final bool ok;
  const _IsolateResult(this.algo, this.type, this.iters, this.totalUs, this.ok);
}

/// Entry point for each worker isolate.
/// Each isolate opens its own handle to libcrypto — perfectly safe in OpenSSL 3.x.
void _isolateWorker(_IsolateArgs args) {
  final pqc = PqcBench(args.libPath);
  final message = Uint8List.fromList(args.message);
  bool ok = true;
  final sw = Stopwatch()..start();

  if (args.type == 'kem') {
    Pointer<EvpPkey>? key;
    for (var i = 0; i < args.iters; i++) {
      key?.let(pqc.freeKey);
      key = pqc.tryKeygen(args.algo);
      if (key == null) {
        ok = false;
        break;
      }
      final (ct, ss1) = pqc.encapsulate(key);
      final ss2 = pqc.decapsulate(key, ct);
      if (!_bytesEqual(ss1, ss2)) ok = false;
    }
    key?.let(pqc.freeKey);
  } else {
    Pointer<EvpPkey>? key = pqc.tryKeygen(args.algo);
    if (key == null) {
      ok = false;
    } else {
      for (var i = 0; i < args.iters; i++) {
        final sig = pqc.sign(key, message);
        if (!pqc.verify(key, message, sig)) ok = false;
      }
      pqc.freeKey(key);
    }
  }

  sw.stop();
  args.sendPort.send(_IsolateResult(
      args.algo, args.type, args.iters, sw.elapsedMicroseconds, ok));
}

/// Run [threads] isolates concurrently, each performing [itersEach] complete
/// keygen+encap+decap (KEM) or keygen+sign+verify (sig) cycles.
/// Returns aggregate ops/sec across all isolates.
Future<({int totalOps, int wallUs, bool ok})> _runConcurrent(
    String libPath, String algo, String type, int threads, int itersEach,
    [List<int> message = const []]) async {
  final receivePort = ReceivePort();
  final results = <_IsolateResult>[];
  final completer = Completer<void>();
  int received = 0;

  receivePort.listen((msg) {
    if (msg is _IsolateResult) {
      results.add(msg);
      received++;
      if (received == threads) completer.complete();
    }
  });

  final wallSw = Stopwatch()..start();
  for (var i = 0; i < threads; i++) {
    await Isolate.spawn(
        _isolateWorker,
        _IsolateArgs(
            receivePort.sendPort, libPath, algo, itersEach, type, message));
  }

  await completer.future;
  wallSw.stop();
  receivePort.close();

  final totalOps = results.fold<int>(0, (s, r) => s + r.iters);
  final ok = results.every((r) => r.ok);
  return (totalOps: totalOps, wallUs: wallSw.elapsedMicroseconds, ok: ok);
}

// ---------------------------------------------------------------------------
// Benchmark runners
// ---------------------------------------------------------------------------

_KemResult? _benchKem(PqcBench pqc, String name, int iters) {
  // Check availability
  final probe = pqc.tryKeygen(name);
  if (probe == null) return null;
  pqc.freeKey(probe);

  stdout.write('  keygen ');
  final keygenTimes = <int>[];
  late Pointer<EvpPkey> lastKey;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    final k = pqc.tryKeygen(name)!;
    sw.stop();
    keygenTimes.add(sw.elapsedMicroseconds);
    if (i < iters - 1) {
      pqc.freeKey(k);
    } else {
      lastKey = k;
    }
    stdout.write('.');
  }
  print('');

  // Encap
  stdout.write('  encap  ');
  final encapTimes = <int>[];
  late Uint8List lastCt, lastSs;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    final (ct, ss) = pqc.encapsulate(lastKey);
    sw.stop();
    encapTimes.add(sw.elapsedMicroseconds);
    lastCt = ct;
    lastSs = ss;
    stdout.write('.');
  }
  print('');

  // Decap
  stdout.write('  decap  ');
  final decapTimes = <int>[];
  late Uint8List decapSs;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    decapSs = pqc.decapsulate(lastKey, lastCt);
    sw.stop();
    decapTimes.add(sw.elapsedMicroseconds);
    stdout.write('.');
  }
  print('');

  pqc.freeKey(lastKey);

  final ssMatch = _bytesEqual(lastSs, decapSs);
  if (!ssMatch) print(chalk.red('  SHARED SECRET MISMATCH!'));

  return _KemResult(
    name,
    _median(keygenTimes),
    _median(encapTimes),
    _median(decapTimes),
    lastCt.length,
    lastSs.length,
    ssMatch,
  );
}

_SigResult? _benchSig(PqcBench pqc, String name, int iters, Uint8List message) {
  final probe = pqc.tryKeygen(name);
  if (probe == null) return null;
  pqc.freeKey(probe);

  stdout.write('  keygen ');
  final keygenTimes = <int>[];
  late Pointer<EvpPkey> lastKey;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    final k = pqc.tryKeygen(name)!;
    sw.stop();
    keygenTimes.add(sw.elapsedMicroseconds);
    if (i < iters - 1) {
      pqc.freeKey(k);
    } else {
      lastKey = k;
    }
    stdout.write('.');
  }
  print('');

  // Sign
  stdout.write('  sign   ');
  final signTimes = <int>[];
  late Uint8List lastSig;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    lastSig = pqc.sign(lastKey, message);
    sw.stop();
    signTimes.add(sw.elapsedMicroseconds);
    stdout.write('.');
  }
  print('');

  // Verify
  stdout.write('  verify ');
  final verifyTimes = <int>[];
  bool verifyOk = true;
  for (var i = 0; i < iters; i++) {
    final sw = Stopwatch()..start();
    final ok = pqc.verify(lastKey, message, lastSig);
    sw.stop();
    verifyTimes.add(sw.elapsedMicroseconds);
    if (!ok) verifyOk = false;
    stdout.write(ok ? '.' : chalk.red('!'));
  }
  print('');

  pqc.freeKey(lastKey);

  if (!verifyOk) print(chalk.red('  VERIFY FAILED!'));

  return _SigResult(
    name,
    _median(keygenTimes),
    _median(signTimes),
    _median(verifyTimes),
    lastSig.length,
    verifyOk,
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int _median(List<int> vals) {
  if (vals.isEmpty) return 0;
  final sorted = List<int>.from(vals)..sort();
  return sorted[sorted.length ~/ 2];
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void _section(String title) => print('\n${chalk.cyan('── $title')}');

String _us(int us) {
  if (us >= 1000000) return '${(us / 1000000).toStringAsFixed(2)} s ';
  if (us >= 1000) return '${(us / 1000).toStringAsFixed(2)} ms';
  return '${us} µs';
}

int _opsPerSec(int us) => us == 0 ? 0 : (1000000 / us).round();

// ---------------------------------------------------------------------------
// Summary printers
// ---------------------------------------------------------------------------

void _printKemSummary(List<_KemResult> results) {
  print('');
  print(chalk.blue('=' * 78));
  print(chalk.blue('ML-KEM (FIPS 203) — KEY ENCAPSULATION'));
  print(chalk.blue('=' * 78));
  print(
      '┌──────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────┐');
  print(
      '│ Algorithm        │ Keygen           │ Encapsulate      │ Decapsulate      │ CT bytes │');
  print(
      '├──────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────┤');
  for (final r in results) {
    final kg = '${_us(r.keygenUs)} (${_opsPerSec(r.keygenUs)}/s)';
    final en = '${_us(r.encapUs)} (${_opsPerSec(r.encapUs)}/s)';
    final de = '${_us(r.decapUs)} (${_opsPerSec(r.decapUs)}/s)';
    final ssOk = r.ssMatch ? '' : chalk.red(' MISMATCH');
    print(
        '│ ${r.name.padRight(16)} │ ${kg.padRight(16)} │ ${en.padRight(16)} │ ${de.padRight(16)} │ ${r.ctBytes.toString().padLeft(8)} │$ssOk');
  }
  print(
      '└──────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────┘');
}

void _printSigSummary(String title, List<_SigResult> results) {
  print('');
  print(chalk.blue('=' * 82));
  print(chalk.blue('$title'));
  print(chalk.blue('=' * 82));
  print(
      '┌──────────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────┐');
  print(
      '│ Algorithm            │ Keygen           │ Sign             │ Verify           │ Sig bytes│');
  print(
      '├──────────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────┤');
  for (final r in results) {
    final kg = '${_us(r.keygenUs)} (${_opsPerSec(r.keygenUs)}/s)';
    final si = '${_us(r.signUs)} (${_opsPerSec(r.signUs)}/s)';
    final ve = '${_us(r.verifyUs)} (${_opsPerSec(r.verifyUs)}/s)';
    final ok = r.verifyOk ? '' : chalk.red(' FAIL');
    print(
        '│ ${r.name.padRight(20)} │ ${kg.padRight(16)} │ ${si.padRight(16)} │ ${ve.padRight(16)} │ ${r.sigBytes.toString().padLeft(8)} │$ok');
  }
  print(
      '└──────────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────┘');
}

// ---------------------------------------------------------------------------
// Concurrent throughput summary
// ---------------------------------------------------------------------------

void _printConcurrentHeader(int threads) {
  print('');
  print(chalk.blue('=' * 82));
  print(chalk.blue(
      'CONCURRENT THROUGHPUT — $threads isolates × libcrypto FFI (true OS threads)'));
  print(chalk.blue('=' * 82));
  print(chalk.yellow(
      'Each isolate opens its own DynamicLibrary handle and runs independently.'));
  print(chalk
      .yellow('Wall-clock time measures from first dispatch to last result.'));
  print('');
  print(
      '┌──────────────────────┬──────────┬──────────┬──────────┬──────────────────┐');
  print(
      '│ Algorithm            │ Threads  │ Ops      │ Wall µs  │ Throughput       │');
  print(
      '├──────────────────────┼──────────┼──────────┼──────────┼──────────────────┤');
}

void _printConcurrentRow(
    String algo, int threads, int ops, int wallUs, double? singleOpsPerSec) {
  final throughput = wallUs == 0 ? 0 : (ops * 1000000 / wallUs).round();
  final scaling = singleOpsPerSec != null && singleOpsPerSec > 0
      ? ' (${(throughput / singleOpsPerSec).toStringAsFixed(2)}×)'
      : '';
  print(
      '│ ${algo.padRight(20)} │ ${threads.toString().padLeft(8)} │ ${ops.toString().padLeft(8)} │ ${wallUs.toString().padLeft(8)} │ ${('$throughput/s$scaling').padRight(16)} │');
}

void _printConcurrentFooter() {
  print(
      '└──────────────────────┴──────────┴──────────┴──────────┴──────────────────┘');
  print(chalk.yellow(
      'Scaling > 1.0 means OpenSSL parallelises well across cores. < 1.0 indicates contention.'));
}

// ---------------------------------------------------------------------------
// Pointer.let helper — avoids null check boilerplate
// ---------------------------------------------------------------------------

extension _PtrLet<T extends NativeType> on Pointer<T> {
  void let(void Function(Pointer<T>) fn) => fn(this);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

Future<void> main(List<String> args) async {
  // Parse args: [iterations] [--threads N]
  int iters = 100;
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
  if (positional.isNotEmpty) iters = int.parse(positional[0]);
  if (threads < 1) threads = 1;

  final slhIters = max(5, iters ~/ 10); // SLH-DSA sign is 10-100× slower

  final path = _libPath();
  print(chalk.cyan('Post-Quantum Cryptography Benchmark'));
  print(chalk.cyan('OpenSSL : $path'));
  print(chalk.cyan('Platform: ${Platform.operatingSystem}'));
  print(chalk
      .cyan('Iters   : KEM/ML-DSA=$iters  SLH-DSA=$slhIters (median of ops)'));
  if (threads > 1)
    print(
        chalk.cyan('Threads : $threads concurrent isolates (throughput mode)'));

  PqcBench pqc;
  try {
    pqc = PqcBench(path);
  } catch (e) {
    print(chalk.red('Could not load OpenSSL from "$path": $e'));
    if (Platform.isMacOS)
      print(chalk.yellow('Install: brew install openssl@3'));
    if (Platform.isLinux)
      print(chalk.yellow('Install: sudo apt-get install libssl-dev'));
    exit(1);
  }

  // 32-byte test message
  final message = Uint8List.fromList(List.generate(32, (i) => i));

  // ── ML-KEM ──────────────────────────────────────────────────────────────
  _section('ML-KEM (FIPS 203) — Key Encapsulation Mechanism');
  final kemAlgos = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];
  final kemResults = <_KemResult>[];
  for (final algo in kemAlgos) {
    print(chalk.cyan('\n  $algo'));
    final r = _benchKem(pqc, algo, iters);
    if (r != null) {
      kemResults.add(r);
      print(chalk.green(
          '  SS match: ${r.ssMatch}  CT: ${r.ctBytes} B  SS: ${r.ssBytes} B'));
    } else {
      print(chalk.yellow('  $algo: NOT AVAILABLE (requires OpenSSL 3.5+)'));
    }
  }

  // ── ML-DSA ──────────────────────────────────────────────────────────────
  _section('ML-DSA (FIPS 204) — Module Lattice Signatures');
  final mlDsaAlgos = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  final mlDsaResults = <_SigResult>[];
  for (final algo in mlDsaAlgos) {
    print(chalk.cyan('\n  $algo'));
    final r = _benchSig(pqc, algo, iters, message);
    if (r != null) {
      mlDsaResults.add(r);
      print(chalk.green('  Verify: ${r.verifyOk}  Sig: ${r.sigBytes} B'));
    } else {
      print(chalk.yellow('  $algo: NOT AVAILABLE (requires OpenSSL 3.5+)'));
    }
  }

  // ── SLH-DSA ─────────────────────────────────────────────────────────────
  _section('SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures');
  print(chalk.yellow(
      '  Note: SLH-DSA-*s (small) variants have very slow sign (~seconds each)'));
  final slhAlgos = [
    'SLH-DSA-SHA2-128s',
    'SLH-DSA-SHA2-128f',
    'SLH-DSA-SHAKE-128s',
    'SLH-DSA-SHAKE-128f',
  ];
  final slhResults = <_SigResult>[];
  for (final algo in slhAlgos) {
    final thisIters = algo.endsWith('s') ? max(3, slhIters ~/ 5) : slhIters;
    print(chalk.cyan('\n  $algo  (iters=$thisIters)'));
    final r = _benchSig(pqc, algo, thisIters, message);
    if (r != null) {
      slhResults.add(r);
      print(chalk.green('  Verify: ${r.verifyOk}  Sig: ${r.sigBytes} B'));
    } else {
      print(chalk.yellow('  $algo: NOT AVAILABLE (requires OpenSSL 3.5+)'));
    }
  }

  // ── Summary tables ───────────────────────────────────────────────────────
  if (kemResults.isNotEmpty) _printKemSummary(kemResults);
  if (mlDsaResults.isNotEmpty)
    _printSigSummary(
        'ML-DSA (FIPS 204) — MODULE LATTICE SIGNATURES', mlDsaResults);
  if (slhResults.isNotEmpty)
    _printSigSummary(
        'SLH-DSA (FIPS 205) — STATELESS HASH-BASED SIGNATURES', slhResults);

  // ── Concurrent throughput ────────────────────────────────────────────────
  if (threads > 1) {
    _section('CONCURRENT THROUGHPUT (--threads $threads)');
    print(chalk.yellow(
        '  Each Dart isolate = OS thread. FFI native calls bypass the Dart event loop.'));
    print(chalk.yellow(
        '  OpenSSL itself is single-threaded per-call; parallelism comes from isolates.'));

    // Build lookup: algo -> single-threaded ops/sec from results above
    final singleOps = <String, double>{};
    for (final r in kemResults) {
      // median of keygen+encap+decap per full cycle
      final cycleUs = r.keygenUs + r.encapUs + r.decapUs;
      if (cycleUs > 0) singleOps[r.name] = 1000000 / cycleUs;
    }
    for (final r in [...mlDsaResults, ...slhResults]) {
      final cycleUs = r.keygenUs + r.signUs + r.verifyUs;
      if (cycleUs > 0) singleOps[r.name] = 1000000 / cycleUs;
    }

    // Iters per isolate: keep total work similar to single-threaded run
    final concIters = max(5, iters ~/ threads);
    final concSlhIters = max(2, slhIters ~/ threads);

    _printConcurrentHeader(threads);

    for (final algo in kemAlgos) {
      final probe = pqc.tryKeygen(algo);
      if (probe == null) continue;
      pqc.freeKey(probe);
      stdout.write('  $algo (${threads}×$concIters ops) ... ');
      final r = await _runConcurrent(path, algo, 'kem', threads, concIters);
      stdout.writeln(r.ok ? 'ok' : chalk.red('MISMATCH'));
      _printConcurrentRow(algo, threads, r.totalOps, r.wallUs, singleOps[algo]);
    }
    for (final algo in mlDsaAlgos) {
      final probe = pqc.tryKeygen(algo);
      if (probe == null) continue;
      pqc.freeKey(probe);
      stdout.write('  $algo (${threads}×$concIters ops) ... ');
      final r = await _runConcurrent(
          path, algo, 'sig', threads, concIters, message.toList());
      stdout.writeln(r.ok ? 'ok' : chalk.red('FAIL'));
      _printConcurrentRow(algo, threads, r.totalOps, r.wallUs, singleOps[algo]);
    }
    for (final algo in slhAlgos) {
      final thisIters =
          algo.endsWith('s') ? max(1, concSlhIters ~/ 2) : concSlhIters;
      final probe = pqc.tryKeygen(algo);
      if (probe == null) continue;
      pqc.freeKey(probe);
      stdout.write('  $algo (${threads}×$thisIters ops) ... ');
      final r = await _runConcurrent(
          path, algo, 'sig', threads, thisIters, message.toList());
      stdout.writeln(r.ok ? 'ok' : chalk.red('FAIL'));
      _printConcurrentRow(algo, threads, r.totalOps, r.wallUs, singleOps[algo]);
    }

    _printConcurrentFooter();
  }

  print('');
  print(chalk.blue('=' * 78));
  print(chalk.blue(
      'All algorithms above are NIST-standardised post-quantum cryptography.'));
  print(chalk.blue(
      'Requires OpenSSL ${Platform.isLinux ? "3.5+" : "3.5+  (Homebrew openssl@3 on macOS)"}'));
  print(chalk.blue('=' * 78));
}
