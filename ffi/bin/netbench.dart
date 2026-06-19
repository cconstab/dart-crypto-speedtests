/// Network crypto benchmark — encrypt locally, send over TCP, decrypt and verify.
///
/// SERVER:  dart run bin/netbench.dart --bind [HOST:]PORT
/// CLIENT:  dart run bin/netbench.dart --to HOST:PORT [options]
///
/// Client options:
///   --algo   aes256ctr|chacha20   cipher            (default: aes256ctr)
///   --size   MB                   block size in MB  (default: 10)
///   --repeat N                    blocks to send    (default: 5)
///   --threads N / -j N            parallel TCP connections (default: 1)
///
/// Build:  dart compile exe bin/netbench.dart -o netbench
///
/// Security note: key + IV are sent in plaintext — benchmark tool only.
///
/// Wire protocol (all multi-byte fields big-endian):
///   Handshake C→S : magic[4] algo[1] key[32] iv[16] repeat[4] blockLen[8] = 65 B
///   Per-block C→S : sha256[32] | ciphertext[blockLen]
///   Summary   S→C : totalBytes[8] okBlocks[4] failBlocks[4] serverDecryptUs[8] = 24 B

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:chalk/chalk.dart';
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

// ---------------------------------------------------------------------------
// OpenSslCrypto — SHA-256, AES-256-CTR, ChaCha20
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

String _installHint() {
  if (Platform.isLinux) return 'Install: sudo apt-get install libssl-dev';
  if (Platform.isMacOS) return 'Install: brew install openssl@3';
  if (Platform.isWindows)
    return 'Download Win64 OpenSSL: https://slproweb.com/products/Win32OpenSSL.html';
  return 'Install OpenSSL for your platform.';
}

// ---------------------------------------------------------------------------
// Wire protocol helpers
// ---------------------------------------------------------------------------

const _algoAes = 0;
const _algoCha = 1;

/// Handshake: 65 bytes — magic(4) algo(1) key(32) iv(16) repeat(4) blockLen(8)
Uint8List _encHandshake(
    int algo, Uint8List key, Uint8List iv, int repeat, int blockLen) {
  final buf = Uint8List(65);
  final bd = ByteData.view(buf.buffer);
  buf[0] = 0x4E;
  buf[1] = 0x45;
  buf[2] = 0x54;
  buf[3] = 0x42; // NETB
  buf[4] = algo;
  buf.setRange(5, 37, key);
  buf.setRange(37, 53, iv);
  bd.setUint32(53, repeat, Endian.big);
  bd.setUint64(57, blockLen, Endian.big);
  return buf;
}

({int algo, Uint8List key, Uint8List iv, int repeat, int blockLen})
    _decHandshake(Uint8List buf) {
  if (buf[0] != 0x4E || buf[1] != 0x45 || buf[2] != 0x54 || buf[3] != 0x42) {
    throw FormatException('Bad magic — expected NETB');
  }
  final bd = ByteData.view(buf.buffer, buf.offsetInBytes);
  return (
    algo: buf[4],
    key: Uint8List.fromList(buf.sublist(5, 37)),
    iv: Uint8List.fromList(buf.sublist(37, 53)),
    repeat: bd.getUint32(53, Endian.big),
    blockLen: bd.getUint64(57, Endian.big),
  );
}

/// Summary: 24 bytes — totalBytes(8) okBlocks(4) failBlocks(4) serverDecryptUs(8)
Uint8List _encSummary(int totalBytes, int ok, int fail, int decryptUs) {
  final buf = Uint8List(24);
  final bd = ByteData.view(buf.buffer);
  bd.setUint64(0, totalBytes, Endian.big);
  bd.setUint32(8, ok, Endian.big);
  bd.setUint32(12, fail, Endian.big);
  bd.setUint64(16, decryptUs, Endian.big);
  return buf;
}

({int totalBytes, int ok, int fail, int decryptUs}) _decSummary(Uint8List buf) {
  final bd = ByteData.view(buf.buffer, buf.offsetInBytes);
  return (
    totalBytes: bd.getUint64(0, Endian.big),
    ok: bd.getUint32(8, Endian.big),
    fail: bd.getUint32(12, Endian.big),
    decryptUs: bd.getUint64(16, Endian.big),
  );
}

bool _bytesEq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Buffered socket reader — reads exact byte counts from a Stream<Uint8List>
// ---------------------------------------------------------------------------

class _Reader {
  final _chunks = <Uint8List>[];
  int _available = 0;
  Completer<void>? _wakeup;
  bool _done = false;
  Object? _error;

  void push(Uint8List data) {
    _chunks.add(data);
    _available += data.length;
    _wakeup?.complete();
    _wakeup = null;
  }

  void close([Object? error]) {
    _done = true;
    _error = error;
    _wakeup?.complete();
    _wakeup = null;
  }

  Future<Uint8List> read(int n) async {
    while (_available < n) {
      if (_error != null) throw _error!;
      if (_done)
        throw StateError('Connection closed before $n bytes (got $_available)');
      _wakeup = Completer();
      await _wakeup!.future;
    }
    final result = Uint8List(n);
    int offset = 0;
    while (offset < n) {
      final chunk = _chunks.first;
      final take = min(n - offset, chunk.length);
      result.setRange(offset, offset + take, chunk);
      offset += take;
      _available -= take;
      if (take == chunk.length) {
        _chunks.removeAt(0);
      } else {
        _chunks[0] = Uint8List.sublistView(chunk, take);
      }
    }
    return result;
  }

  /// Yields all remaining buffered bytes, then future bytes as they arrive.
  /// The external subscription feeding push() must remain active.
  Stream<Uint8List> rest() async* {
    while (true) {
      while (_chunks.isNotEmpty) {
        final chunk = _chunks.removeAt(0);
        _available -= chunk.length;
        yield chunk;
      }
      if (_error != null) throw _error!;
      if (_done) return;
      _wakeup = Completer();
      await _wakeup!.future;
    }
  }
}

// ---------------------------------------------------------------------------
// Stream transformers — hash+encrypt (client) and decrypt+verify (server)
// ---------------------------------------------------------------------------

/// Per-block result emitted by [CryptoDecodeTransformer].
class _DecodeEvent {
  final int bytes;
  final int decryptUs;
  final bool hashOk;
  const _DecodeEvent(this.bytes, this.decryptUs, this.hashOk);
}

/// Client-side transformer: takes a stream of plaintext blocks, computes
/// SHA-256 and encrypts each block, yields [hash(32) || ciphertext] frames.
/// Accumulates [hashUs] and [encryptUs] for reporting.
class CryptoEncodeTransformer
    extends StreamTransformerBase<Uint8List, Uint8List> {
  final OpenSslCrypto _crypto;
  final int _algo;
  final Uint8List _key;
  final Uint8List _iv;

  int hashUs = 0;
  int encryptUs = 0;

  CryptoEncodeTransformer(this._crypto, this._algo, this._key, this._iv);

  @override
  Stream<Uint8List> bind(Stream<Uint8List> stream) async* {
    await for (final block in stream) {
      final hashSw = Stopwatch()..start();
      final hash = _crypto.sha256(block);
      hashUs += hashSw.elapsedMicroseconds;

      final encSw = Stopwatch()..start();
      final cipher = _algo == _algoAes
          ? _crypto.aes256CtrEncrypt(block, _key, _iv)
          : _crypto.chacha20Encrypt(block, _key, _iv);
      encryptUs += encSw.elapsedMicroseconds;

      // Emit hash || ciphertext as a single wire frame.
      final frame = Uint8List(32 + cipher.length);
      frame.setRange(0, 32, hash);
      frame.setRange(32, 32 + cipher.length, cipher);
      yield frame;
    }
  }
}

/// Server-side transformer: receives raw bytes (post-handshake), buffers them
/// internally, and for each complete [hash(32) || ciphertext(blockLen)] frame
/// decrypts and hash-verifies, yielding a [_DecodeEvent] per block.
class CryptoDecodeTransformer
    extends StreamTransformerBase<Uint8List, _DecodeEvent> {
  final OpenSslCrypto _crypto;
  final int _algo;
  final Uint8List _key;
  final Uint8List _iv;
  final int _blockLen;
  final int _repeat;

  CryptoDecodeTransformer(this._crypto, this._algo, this._key, this._iv,
      this._blockLen, this._repeat);

  @override
  Stream<_DecodeEvent> bind(Stream<Uint8List> incoming) {
    final ctrl = StreamController<_DecodeEvent>();
    final reader = _Reader();
    final sub = incoming.listen(
      reader.push,
      onDone: () => reader.close(),
      onError: (e) => reader.close(e),
    );

    unawaited(Future(() async {
      try {
        for (var i = 0; i < _repeat; i++) {
          final sentHash = await reader.read(32);
          final ciphertext = await reader.read(_blockLen);

          final sw = Stopwatch()..start();
          final plain = _algo == _algoAes
              ? _crypto.aes256CtrDecrypt(ciphertext, _key, _iv)
              : _crypto.chacha20Decrypt(ciphertext, _key, _iv);
          sw.stop();

          final hashOk = _bytesEq(sentHash, _crypto.sha256(plain));
          ctrl.add(
              _DecodeEvent(ciphertext.length, sw.elapsedMicroseconds, hashOk));
        }
      } catch (e, st) {
        ctrl.addError(e, st);
      } finally {
        await sub.cancel();
        ctrl.close();
      }
    }));

    return ctrl.stream;
  }
}

// ---------------------------------------------------------------------------
// Server — connection handler (runs async in the server's event loop)
// ---------------------------------------------------------------------------

Future<void> _handleConn(Socket socket, String libPath) async {
  final peer = '${socket.remoteAddress.address}:${socket.remotePort}';
  final reader = _Reader();
  // sub feeds reader for both handshake and block frames via reader.rest()
  final sub = socket.listen(
    reader.push,
    onDone: () => reader.close(),
    onError: (e) => reader.close(e),
    cancelOnError: false,
  );
  final crypto = OpenSslCrypto(libPath);
  try {
    final hs = _decHandshake(await reader.read(65));
    final algoName = hs.algo == _algoAes ? 'AES-256-CTR' : 'ChaCha20';
    crypto.prewarm(hs.blockLen);
    print(chalk.cyan(
        '  [$peer] $algoName  ${hs.blockLen ~/ (1024 * 1024)} MB × ${hs.repeat} blocks'));

    // Pipe remaining socket bytes through the decode+verify transformer.
    final decoder = CryptoDecodeTransformer(
        crypto, hs.algo, hs.key, hs.iv, hs.blockLen, hs.repeat);

    int totalBytes = 0, okBlocks = 0, failBlocks = 0, decryptUs = 0;

    await for (final event in reader.rest().transform(decoder)) {
      final blockIdx = okBlocks + failBlocks + 1;
      totalBytes += event.bytes;
      decryptUs += event.decryptUs;
      if (event.hashOk)
        okBlocks++;
      else
        failBlocks++;

      final mbps = event.decryptUs == 0
          ? 0
          : (event.bytes * 8 / 1e6 / (event.decryptUs / 1e6)).round();
      print('  [$peer] block $blockIdx/${hs.repeat}  '
          '${event.hashOk ? chalk.green("hash ok") : chalk.red("HASH MISMATCH")}  '
          '— decrypt $mbps Mbps');
    }

    socket.add(_encSummary(totalBytes, okBlocks, failBlocks, decryptUs));
    await socket.flush();

    final totalMbps =
        decryptUs == 0 ? 0 : (totalBytes * 8 / 1e6 / (decryptUs / 1e6)).round();
    print(chalk.green(
        '  [$peer] done  ok=$okBlocks  fail=$failBlocks  server-decrypt=$totalMbps Mbps'));
  } catch (e) {
    print(chalk.red('  [$peer] error: $e'));
  } finally {
    await sub.cancel();
    socket.destroy();
    crypto.dispose();
  }
}

// ---------------------------------------------------------------------------
// Server main
// ---------------------------------------------------------------------------

Future<void> _runServer(String host, int port) async {
  final libPath = _libPath();
  try {
    final c = OpenSslCrypto(libPath);
    c.dispose();
  } catch (e) {
    stderr.writeln(chalk.red('Cannot load OpenSSL from "$libPath": $e'));
    stderr.writeln(chalk.yellow(_installHint()));
    exit(1);
  }

  final addr = host == '0.0.0.0'
      ? InternetAddress.anyIPv4
      : host == '::'
          ? InternetAddress.anyIPv6
          : InternetAddress(host);
  final server = await ServerSocket.bind(addr, port);
  print(chalk.cyan('netbench server  —  listening on $host:$port'));
  print(chalk.cyan('OpenSSL : $libPath'));
  print(chalk.yellow('Press Ctrl+C to stop.\n'));

  await for (final socket in server) {
    socket.setOption(SocketOption.tcpNoDelay, true);
    print(chalk.cyan(
        'Connection from ${socket.remoteAddress.address}:${socket.remotePort}'));
    // Fire-and-forget: concurrent connections handled by the async event loop.
    // Each connection uses its own OpenSslCrypto instance — no shared state.
    unawaited(_handleConn(socket, libPath));
  }
}

// ---------------------------------------------------------------------------
// Client — isolate worker (one per --threads connection)
// ---------------------------------------------------------------------------

class _ClientArgs {
  final SendPort sendPort;
  final String libPath;
  final String host;
  final int port;
  final int algo;
  final int blockBytes;
  final int repeat;
  final int threadId;
  const _ClientArgs(this.sendPort, this.libPath, this.host, this.port,
      this.algo, this.blockBytes, this.repeat, this.threadId);
}

class _ClientResult {
  final int threadId;
  final int wireBytes; // total plaintext bytes sent
  final int wallUs; // total time: encrypt + TCP + server ack
  final int okBlocks;
  final int failBlocks;
  final int serverDecryptUs; // pure OpenSSL decrypt time on server
  final int clientHashUs; // SHA-256 time on client
  final int clientEncryptUs; // cipher time on client
  final bool hasError;
  final String errorMsg;
  const _ClientResult(this.threadId, this.wireBytes, this.wallUs, this.okBlocks,
      this.failBlocks, this.serverDecryptUs,
      {this.clientHashUs = 0,
      this.clientEncryptUs = 0,
      this.hasError = false,
      this.errorMsg = ''});
}

/// Fills a Uint8List with pseudo-random bytes using 4-byte chunks for speed.
Uint8List _randomData(int n) {
  final buf = Uint8List(n);
  final view = buf.buffer.asInt32List();
  final rng = Random();
  for (var i = 0; i < view.length; i++) view[i] = rng.nextInt(0x7fffffff);
  // Fill any trailing bytes not covered by 4-byte chunks
  for (var i = view.length * 4; i < n; i++) buf[i] = rng.nextInt(256);
  return buf;
}

Future<void> _clientWorker(_ClientArgs args) async {
  final crypto = OpenSslCrypto(args.libPath);
  final secRng = Random.secure();

  // Key + IV use CSPRNG; plaintext uses fast PRNG (benchmark, not a protocol)
  final key = Uint8List.fromList(List.generate(32, (_) => secRng.nextInt(256)));
  final iv = Uint8List.fromList(List.generate(16, (_) => secRng.nextInt(256)));

  try {
    // Generate plaintext once; reuse for all blocks (throughput test)
    final plain = _randomData(args.blockBytes);
    final encoder = CryptoEncodeTransformer(crypto, args.algo, key, iv);

    final socket = await Socket.connect(args.host, args.port);
    socket.setOption(SocketOption.tcpNoDelay, true);

    final reader = _Reader();
    socket.listen(
      reader.push,
      onDone: () => reader.close(),
      onError: (e) => reader.close(e),
      cancelOnError: false,
    );

    final sw = Stopwatch()..start();

    // Send handshake
    socket.add(_encHandshake(args.algo, key, iv, args.repeat, args.blockBytes));

    // Hash+encrypt each block through the transformer, send immediately.
    // Wall clock includes encrypt + TCP send for all blocks.
    final blockStream =
        Stream.fromIterable(List.generate(args.repeat, (_) => plain));
    await for (final frame in blockStream.transform(encoder)) {
      socket.add(frame);
    }
    await socket.flush();

    // Wait for server summary (sent after server processes all blocks)
    final summary = _decSummary(await reader.read(24));
    sw.stop();

    socket.destroy();
    crypto.dispose();

    args.sendPort.send(_ClientResult(
        args.threadId,
        args.blockBytes * args.repeat,
        sw.elapsedMicroseconds,
        summary.ok,
        summary.fail,
        summary.decryptUs,
        clientHashUs: encoder.hashUs,
        clientEncryptUs: encoder.encryptUs));
  } catch (e) {
    crypto.dispose();
    args.sendPort.send(_ClientResult(args.threadId, 0, 0, 0, 0, 0,
        hasError: true, errorMsg: e.toString()));
  }
}

// ---------------------------------------------------------------------------
// Client main
// ---------------------------------------------------------------------------

Future<void> _runClient(String host, int port, int algo, int blockMb,
    int repeat, int threads) async {
  final libPath = _libPath();
  final algoName = algo == _algoAes ? 'AES-256-CTR' : 'ChaCha20';
  final blockBytes = blockMb * 1024 * 1024;

  print(chalk.cyan('netbench client  →  $host:$port'));
  print(chalk.cyan('OpenSSL  : $libPath'));
  print(chalk.cyan('Cipher   : $algoName'));
  print(chalk.cyan(
      'Data     : $blockMb MB × $repeat blocks × $threads parallel connection(s)'));
  print(chalk.yellow(
      'Note: key+IV sent in plaintext — benchmark tool only, not a secure protocol.'));
  print('');

  final receivePort = ReceivePort();
  final results = <_ClientResult>[];
  final completer = Completer<void>();
  int received = 0;

  receivePort.listen((msg) {
    if (msg is _ClientResult) {
      results.add(msg);
      received++;
      if (received == threads) completer.complete();
    }
  });

  for (var i = 0; i < threads; i++) {
    await Isolate.spawn(
        _clientWorker,
        _ClientArgs(receivePort.sendPort, libPath, host, port, algo, blockBytes,
            repeat, i));
  }

  stdout.write('  Running ($threads connection(s) in parallel)...');
  await completer.future;
  receivePort.close();
  print('  done.\n');

  // ── Report ──────────────────────────────────────────────────────────────

  final errors = results.where((r) => r.hasError).toList();
  final successes = results.where((r) => !r.hasError).toList();

  for (final e in errors) {
    print(chalk.red('  Thread ${e.threadId}: ${e.errorMsg}'));
  }
  if (successes.isEmpty) {
    print(chalk.red('All connections failed.'));
    return;
  }

  final totalWireBytes = successes.fold<int>(0, (s, r) => s + r.wireBytes);
  final totalOk = successes.fold<int>(0, (s, r) => s + r.okBlocks);
  final totalFail = successes.fold<int>(0, (s, r) => s + r.failBlocks);
  // Use slowest thread's wall time for true parallel throughput
  final maxWallUs =
      successes.fold<int>(0, (m, r) => r.wallUs > m ? r.wallUs : m);
  // CPU times: sum across connections (they ran in parallel on separate cores)
  final totalSrvDecUs = successes.fold<int>(0, (s, r) => s + r.serverDecryptUs);
  final totalClientHashUs =
      successes.fold<int>(0, (s, r) => s + r.clientHashUs);
  final totalClientEncUs =
      successes.fold<int>(0, (s, r) => s + r.clientEncryptUs);

  int _mbps(int totalBytes, int cpuUs) =>
      cpuUs == 0 ? 0 : (totalBytes * 8 / 1e6 / (cpuUs / 1e6)).round();

  final wireMbps = _mbps(totalWireBytes, maxWallUs);
  final srvDecMbps = _mbps(totalWireBytes, totalSrvDecUs);
  final clientHashMbps = _mbps(totalWireBytes, totalClientHashUs);
  final clientEncMbps = _mbps(totalWireBytes, totalClientEncUs);

  final hashStatus = totalFail == 0
      ? chalk.green('✓ all $totalOk blocks verified')
      : chalk.red('$totalFail HASH MISMATCH(ES) — data corrupted in transit!');

  print(chalk.blue('═' * 64));
  print(chalk.blue('  NETWORK CRYPTO BENCHMARK RESULTS'));
  print(chalk.blue('═' * 64));
  print('  Target    : $host:$port');
  print('  Cipher    : $algoName');
  print(
      '  Data      : $blockMb MB × $repeat blocks × ${successes.length} thread(s)');
  print('  Integrity : $hashStatus');
  print('');
  print('  ┌──────────────────────────────────────┬─────────────┐');
  print('  │ Metric                               │    Speed    │');
  print('  ├──────────────────────────────────────┼─────────────┤');
  print(
      '  │ Client SHA-256 hash                  │ ${('$clientHashMbps Mbps').padLeft(11)} │');
  print(
      '  │ Client encrypt (OpenSSL FFI)         │ ${('$clientEncMbps Mbps').padLeft(11)} │');
  print(
      '  │ Wire throughput (client wall time)   │ ${('$wireMbps Mbps').padLeft(11)} │');
  print(
      '  │ Server decrypt (OpenSSL FFI)         │ ${('$srvDecMbps Mbps').padLeft(11)} │');
  print('  └──────────────────────────────────────┴─────────────┘');
  print('');
  print(chalk.yellow(
      '  Client hash/encrypt = pure OpenSSL CPU time on sender (excludes TCP).'));
  print(chalk.yellow(
      '  Wire = encrypt + TCP send + server decrypt + TCP reply (wall clock).'));
  print(chalk.yellow(
      '  Server decrypt = pure OpenSSL CPU time on receiver (excludes network).'));

  if (threads > 1 && successes.length > 1) {
    // Per-thread average for scaling comparison
    final avgPerThreadUs =
        successes.fold<int>(0, (s, r) => s + r.wallUs) ~/ successes.length;
    final singleMbps = avgPerThreadUs == 0
        ? 0
        : ((blockBytes * repeat) * 8 / 1e6 / (avgPerThreadUs / 1e6)).round();
    if (singleMbps > 0) {
      final scaling = (wireMbps / singleMbps).toStringAsFixed(2);
      print(chalk.yellow(
          '  Per-thread avg : $singleMbps Mbps  →  ${scaling}× scaling across $threads threads'));
    }
  }
  print(chalk.blue('═' * 64));
}

// ---------------------------------------------------------------------------
// Address parser — supports HOST:PORT, PORT, [IPv6]:PORT
// ---------------------------------------------------------------------------

(String, int) _parseAddr(String addr, {required String defaultHost}) {
  if (addr.startsWith('[')) {
    // [IPv6]:PORT
    final end = addr.indexOf(']');
    if (end < 0) throw FormatException('Invalid IPv6 address: $addr');
    return (addr.substring(1, end), int.parse(addr.substring(end + 2)));
  }
  final colon = addr.lastIndexOf(':');
  if (colon < 0) {
    // Just a port number
    return (defaultHost, int.parse(addr));
  }
  final host = addr.substring(0, colon);
  final port = int.parse(addr.substring(colon + 1));
  return (host.isEmpty ? defaultHost : host, port);
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

void _usage() => print('''
netbench — AES-256-CTR / ChaCha20 throughput over a real TCP connection.
Encrypt on sender, send over network, decrypt and SHA-256 verify on receiver.

  SERVER:  dart run bin/netbench.dart --bind [HOST:]PORT
  CLIENT:  dart run bin/netbench.dart --to HOST:PORT [options]

  --algo   aes256ctr|chacha20   cipher            (default: aes256ctr)
  --size   MB                   block size in MB  (default: 10)
  --repeat N                    blocks to send    (default: 5)
  --threads N / -j N            parallel connections (default: 1)

Examples:
  # Machine A (server):
  dart run bin/netbench.dart --bind 0.0.0.0:9999

  # Machine B (client, 64 MB blocks, 10 rounds, 4 parallel connections):
  dart run bin/netbench.dart --to 192.168.1.10:9999 --size 64 --repeat 10 --threads 4

  # Loopback test:
  dart run bin/netbench.dart --bind 127.0.0.1:9999 &
  dart run bin/netbench.dart --to 127.0.0.1:9999 --algo chacha20 --size 100 --repeat 3
''');

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

Future<void> main(List<String> args) async {
  String? bindAddr;
  String? toAddr;
  String algo = 'aes256ctr';
  int blockMb = 10;
  int repeat = 5;
  int threads = 1;

  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--bind':
        bindAddr = args[++i];
      case '--to':
        toAddr = args[++i];
      case '--algo':
        algo = args[++i];
      case '--size':
        blockMb = int.parse(args[++i]);
      case '--repeat':
        repeat = int.parse(args[++i]);
      case '--threads' || '-j':
        threads = int.parse(args[++i]);
      default:
        stderr.writeln('Unknown argument: ${args[i]}');
        _usage();
        exit(1);
    }
  }

  if (bindAddr == null && toAddr == null) {
    _usage();
    exit(1);
  }
  if (bindAddr != null && toAddr != null) {
    stderr.writeln('Specify either --bind or --to, not both.');
    exit(1);
  }
  if (threads < 1) threads = 1;

  if (bindAddr != null) {
    final (host, port) = _parseAddr(bindAddr, defaultHost: '0.0.0.0');
    await _runServer(host, port);
  } else {
    final (host, port) = _parseAddr(toAddr!, defaultHost: '127.0.0.1');
    final algoCode = switch (algo.toLowerCase()) {
      'aes256ctr' || 'aes' => _algoAes,
      'chacha20' || 'cha' => _algoCha,
      _ =>
        throw ArgumentError('Unknown algo "$algo". Use: aes256ctr, chacha20'),
    };
    await _runClient(host, port, algoCode, blockMb, repeat, threads);
  }
}
