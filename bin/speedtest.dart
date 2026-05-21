import 'package:boring/boring.dart'; // OpenSslCrypto, getOpenSslLibPath
import 'dart:typed_data';
import 'dart:convert' show utf8;
import 'dart:ffi' show DynamicLibrary; // needed by sodiumTest
import 'dart:io';
import 'dart:math';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
// ignore: depend_on_referenced_packages
import 'package:better_cryptography/better_cryptography.dart' as better;
import 'package:encrypt/encrypt.dart';
import 'package:chalk/chalk.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/stream/chacha20.dart';
import 'package:fastcrypt/fastcrypt.dart';
import 'package:sodium/sodium.dart';

void _fillRandom(Uint8List bytes) {
  final rng = Random.secure();
  for (var i = 0; i < bytes.length; i++) bytes[i] = rng.nextInt(256);
}

// Emit a one-line summary of CPU crypto features (best-effort, Linux only).
void printCpuFeatures() {
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
    if (found.isNotEmpty) {
      print(chalk.cyan('CPU hw-accel flags: ${found.join(', ')}'));
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------

class TestResult {
  final String name;
  final int mbps;
  final int timeMs;

  TestResult(this.name, this.mbps, this.timeMs);
}

Future<void> main(List<String> arguments) async {
  if (arguments.length != 2) {
    print('speedtest <file size in MB> <repeat n times>');
    exit(1);
  }
  int mBytes = int.parse(arguments[0]) * 1024 * 1024;
  final String text = getRandomString(mBytes);
  int repeat = int.parse(arguments[1]);

  // Pre-encode once – every test function receives the same Uint8List.
  final Uint8List inputBytes = Uint8List.fromList(utf8.encode(text));

  printCpuFeatures();

  List<TestResult> allResults = [];

  OpenSslCrypto? openssl;
  try {
    openssl = OpenSslCrypto(getOpenSslLibPath());
    print('OpenSSL loaded from: ${getOpenSslLibPath()}');
    openssl.prewarm(inputBytes.length);
  } catch (e) {
    print(chalk.yellow('OpenSSL not available: $e'));
  }

  OpenSslPkgCrypto? opensslPkg;
  try {
    opensslPkg = OpenSslPkgCrypto();
    opensslPkg.prewarm(inputBytes.length);
    print('OpenSSL pkg loaded (Native Assets)');
  } catch (e) {
    print(chalk.yellow('OpenSSL pkg not available: $e'));
  }

  line();
  allResults.addAll(await hashTest(text, inputBytes, repeat, openssl: openssl));
  line();
  allResults.addAll(await aesctrTest(text, inputBytes, repeat, openssl: openssl));
  line();
  allResults.addAll(fastcryptTest(text, repeat));
  line();
  allResults.addAll(await chacha20Test(text, inputBytes, repeat, openssl: openssl));
  line();
  allResults.addAll(await sodiumTest(text, inputBytes, repeat));
  line();

  if (opensslPkg != null) {
    allResults.addAll(opensslPkgTest(inputBytes, repeat, pkgCrypto: opensslPkg));
    line();
  }

  openssl?.dispose();
  opensslPkg?.dispose();

  // Summary
  print('');
  print('${chalk.blue('=' * 80)}');
  print('${chalk.blue('PERFORMANCE SUMMARY')}');
  print('${chalk.blue('=' * 80)}');
  print('Test Parameters:');
  print('  • Data Size: ${(mBytes / 1024 / 1024).toStringAsFixed(1)} MB');
  print('  • Iterations: $repeat');
  print('');

  final hashResults = allResults.where((r) => r.name.contains('SHA256')).toList();
  final encResults  = allResults.where((r) => !r.name.contains('SHA256')).toList();

  if (hashResults.isNotEmpty) {
    print('${chalk.yellow('HASH ALGORITHM PERFORMANCE:')}');
    print('');
    print('┌───────────────────────────────────┬─────────────┬───────────────┐');
    print('│ Algorithm                         │   Time (ms) │  Speed (mbps) │');
    print('├───────────────────────────────────┼─────────────┼───────────────┤');
    for (var r in hashResults) {
      print('│ ${r.name.padRight(33)} │   ${r.timeMs.toString().padLeft(9)} │   ${r.mbps.toString().padLeft(11)} │');
    }
    print('└───────────────────────────────────┴─────────────┴───────────────┘');
    print('');
  }

  if (encResults.isNotEmpty) {
    print('${chalk.yellow('ENCRYPTION ALGORITHM PERFORMANCE:')}');
    print('');
    print('┌───────────────────────────────────┬─────────────┬───────────────┐');
    print('│ Algorithm                         │   Time (ms) │  Speed (mbps) │');
    print('├───────────────────────────────────┼─────────────┼───────────────┤');
    for (var r in encResults) {
      print('│ ${r.name.padRight(33)} │   ${r.timeMs.toString().padLeft(9)} │   ${r.mbps.toString().padLeft(11)} │');
    }
    print('└───────────────────────────────────┴─────────────┴───────────────┘');
    print('');
  }

  if (hashResults.isNotEmpty) {
    final best = hashResults.reduce((a, b) => a.mbps > b.mbps ? a : b);
    print('${chalk.green('🏆 Best Hash Performance:')} ${best.name} (${best.mbps} mbps)');
  }
  if (encResults.isNotEmpty) {
    final best = encResults.reduce((a, b) => a.mbps > b.mbps ? a : b);
    print('${chalk.green('🏆 Best Encryption Performance:')} ${best.name} (${best.mbps} mbps)');
  }
  print('${chalk.blue('=' * 70)}');
}

void line() {
  print('-----------------------------------------------');
}

// Runs [fn] [n] times without timing – warms up the JIT and CPU caches.
Future<void> _warmupAsync(int n, Future<void> Function() fn) async {
  for (var i = 0; i < n; i++) await fn();
}
void _warmup(int n, void Function() fn) {
  for (var i = 0; i < n; i++) fn();
}

int _mbps(int dataBytes, int repeat, int ms) =>
    ms == 0 ? 0 : (((dataBytes * 8 * repeat) / 1000000) / (ms / 1000)).round();

// ---------------------------------------------------------------------------
// Hash tests
// ---------------------------------------------------------------------------

Future<List<TestResult>> hashTest(
  String text,
  Uint8List inputBytes,
  int repeat, {
  OpenSslCrypto? openssl,
}) async {
  List<TestResult> results = [];
  final warmups = min(2, repeat);
  print("String length: ${(inputBytes.length / 1024).toStringAsFixed(0)} KB");

  // --- Crypto SHA-256 ---
  line();
  print("Start software CRYPTO SHA256");
  _warmup(warmups, () => crypto.sha256.convert(inputBytes));
  int count = 0;
  final sw = Stopwatch()..start();
  while (count < repeat) {
    crypto.sha256.convert(inputBytes);
    stdout.write('.');
    count++;
  }
  sw.stop();
  var softwareMs = sw.elapsedMilliseconds;
  var mbps = _mbps(inputBytes.length, repeat, softwareMs);
  print("\n$softwareMs ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('Crypto SHA256', mbps, softwareMs));

  // --- Better SHA-256 ---
  line();
  print("Start Better SHA256");
  var betterSha = better.Sha256();
  _warmup(warmups, () => betterSha.hash(inputBytes));
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    betterSha.hash(inputBytes);
    stdout.write('.');
    count++;
  }
  sw.stop();
  var betterMs = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, betterMs);
  print("\n$betterMs ms  ${chalk.green('$mbps')} mbps");
  var pct = betterMs == 0 ? 0 : ((softwareMs / betterMs) * 100).round() - 100;
  print("Better vs Crypto: ${chalk.green("$pct")}%");
  results.add(TestResult('Better SHA256', mbps, betterMs));

  // --- OpenSSL SHA-256 ---
  if (openssl != null) {
    line();
    print("Start OpenSSL SHA256");
    _warmup(warmups, () => openssl.sha256(inputBytes));
    count = 0;
    sw..reset()..start();
    while (count < repeat) {
      openssl.sha256(inputBytes);
      stdout.write('.');
      count++;
    }
    sw.stop();
    var opensslMs = sw.elapsedMilliseconds;
    mbps = _mbps(inputBytes.length, repeat, opensslMs);
    print("\n$opensslMs ms  ${chalk.green('$mbps')} mbps");
    pct = opensslMs == 0 ? 0 : ((softwareMs / opensslMs) * 100).round() - 100;
    print("OpenSSL vs Crypto: ${chalk.green("$pct")}%");
    results.add(TestResult('OpenSSL SHA256', mbps, opensslMs));
  }

  return results;
}

// ---------------------------------------------------------------------------
// AES-CTR tests
// ---------------------------------------------------------------------------

Future<List<TestResult>> aesctrTest(
  String text,
  Uint8List inputBytes,
  int repeat, {
  OpenSslCrypto? openssl,
}) async {
  List<TestResult> results = [];
  final warmups = min(2, repeat);
  line();
  print("String length: ${(inputBytes.length / 1024).toStringAsFixed(0)} KB");

  // --- Software AES-CTR (encrypt package) ---
  line();
  print("Start software AES-CTR");
  final encKey = Key.fromUtf8('my 32 length key................');
  final encIv  = IV.fromLength(16);
  final encrypter = Encrypter(AES(encKey, mode: AESMode.ctr));
  // encryptBytes/decryptBytes avoid internal String↔bytes conversion.
  _warmup(warmups, () {
    final enc = encrypter.encryptBytes(inputBytes, iv: encIv);
    encrypter.decryptBytes(enc, iv: encIv);
  });
  int count = 0;
  final sw = Stopwatch()..start();
  while (count < repeat) {
    final enc = encrypter.encryptBytes(inputBytes, iv: encIv);
    final dec = encrypter.decryptBytes(enc, iv: encIv);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  var softwareMs = sw.elapsedMilliseconds;
  var mbps = _mbps(inputBytes.length, repeat, softwareMs);
  print("\n$softwareMs ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('Software AES-CTR', mbps, softwareMs));

  // --- Better AES-CTR ---
  line();
  print("Start Better AES-CTR");
  better.AesCtr bAlgorithm = better.AesCtr.with256bits(macAlgorithm: better.Hmac.sha256());
  var bSecretKey = await bAlgorithm.newSecretKey();
  final bctr = Uint8List(16);
  _fillRandom(bctr);
  await _warmupAsync(warmups, () async {
    final box = await bAlgorithm.encrypt(inputBytes, secretKey: bSecretKey, nonce: bctr);
    await bAlgorithm.decrypt(box, secretKey: bSecretKey);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final box = await bAlgorithm.encrypt(inputBytes, secretKey: bSecretKey, nonce: bctr);
    final dec = await bAlgorithm.decrypt(box, secretKey: bSecretKey);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  var betterMs = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, betterMs);
  print("\n$betterMs ms  ${chalk.green('$mbps')} mbps");
  var pct = betterMs == 0 ? 0 : ((softwareMs / betterMs) * 100).round() - 100;
  print("Better vs Software: ${chalk.green("$pct")}%");
  results.add(TestResult('Better AES-CTR', mbps, betterMs));

  // --- OpenSSL AES-256-CTR ---
  if (openssl != null) {
    line();
    print("Start OpenSSL AES-256-CTR");
    final sslKey = Uint8List(32);
    final sslIv  = Uint8List(16);
    _fillRandom(sslKey);
    _fillRandom(sslIv);
    _warmup(warmups, () {
      final enc = openssl.aes256CtrEncrypt(inputBytes, sslKey, sslIv);
      openssl.aes256CtrDecrypt(enc, sslKey, sslIv);
    });
    count = 0;
    sw..reset()..start();
    while (count < repeat) {
      final enc = openssl.aes256CtrEncrypt(inputBytes, sslKey, sslIv);
      final dec = openssl.aes256CtrDecrypt(enc, sslKey, sslIv);
      stdout.write(const ListEquality().equals(dec, inputBytes)
          ? chalk.green(".") : chalk.red("."));
      count++;
    }
    sw.stop();
    var opensslMs = sw.elapsedMilliseconds;
    mbps = _mbps(inputBytes.length, repeat, opensslMs);
    print("\n$opensslMs ms  ${chalk.green('$mbps')} mbps");
    pct = opensslMs == 0 ? 0 : ((softwareMs / opensslMs) * 100).round() - 100;
    print("OpenSSL vs Software: ${chalk.green("$pct")}%");
    results.add(TestResult('OpenSSL AES-256-CTR', mbps, opensslMs));
  }

  return results;
}

// ---------------------------------------------------------------------------
// ChaCha20 tests
// ---------------------------------------------------------------------------

Future<List<TestResult>> chacha20Test(
  String text,
  Uint8List inputBytes,
  int repeat, {
  OpenSslCrypto? openssl,
}) async {
  List<TestResult> results = [];
  final warmups = min(2, repeat);
  line();
  print("String length: ${(inputBytes.length / 1024).toStringAsFixed(0)} KB");

  // --- PointyCastle ChaCha20 ---
  line();
  print("Start PointyCastle ChaCha20");
  final pcKey   = Uint8List(32);
  final pcNonce = Uint8List(8);
  _fillRandom(pcKey);
  _fillRandom(pcNonce);
  // Pre-allocate output buffers – reused every iteration.
  final pcEncrypted = Uint8List(inputBytes.length);
  final pcDecrypted = Uint8List(inputBytes.length);
  final pcCipher = ChaCha20Engine();
  _warmup(warmups, () {
    pcCipher.init(true,  ParametersWithIV(KeyParameter(pcKey), pcNonce));
    pcCipher.processBytes(inputBytes, 0, inputBytes.length, pcEncrypted, 0);
    pcCipher.init(false, ParametersWithIV(KeyParameter(pcKey), pcNonce));
    pcCipher.processBytes(pcEncrypted, 0, pcEncrypted.length, pcDecrypted, 0);
  });
  int count = 0;
  final sw = Stopwatch()..start();
  while (count < repeat) {
    pcCipher.init(true,  ParametersWithIV(KeyParameter(pcKey), pcNonce));
    pcCipher.processBytes(inputBytes, 0, inputBytes.length, pcEncrypted, 0);
    pcCipher.init(false, ParametersWithIV(KeyParameter(pcKey), pcNonce));
    pcCipher.processBytes(pcEncrypted, 0, pcEncrypted.length, pcDecrypted, 0);
    stdout.write(const ListEquality().equals(pcDecrypted, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  var pcMs = sw.elapsedMilliseconds;
  var mbps = _mbps(inputBytes.length, repeat, pcMs);
  print("\n$pcMs ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('PointyCastle ChaCha20', mbps, pcMs));

  // --- Better ChaCha20 ---
  line();
  print("Start Better ChaCha20");
  final bChacha = better.Chacha20.poly1305Aead();
  var bSecretKey = await bChacha.newSecretKey();
  final bNonce = Uint8List(12);
  _fillRandom(bNonce);
  await _warmupAsync(warmups, () async {
    final box = await bChacha.encrypt(inputBytes, secretKey: bSecretKey, nonce: bNonce);
    await bChacha.decrypt(box, secretKey: bSecretKey);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final box = await bChacha.encrypt(inputBytes, secretKey: bSecretKey, nonce: bNonce);
    final dec = await bChacha.decrypt(box, secretKey: bSecretKey);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  var betterMs = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, betterMs);
  print("\n$betterMs ms  ${chalk.green('$mbps')} mbps");
  var pct = betterMs == 0 ? 0 : ((pcMs / betterMs) * 100).round() - 100;
  print(pct > 0
      ? "Better faster than PC: ${chalk.green("$pct")}%"
      : "PointyCastle faster than Better: ${chalk.green("${-pct}")}%");
  results.add(TestResult('Better ChaCha20', mbps, betterMs));

  // --- OpenSSL ChaCha20 ---
  if (openssl != null) {
    line();
    print("Start OpenSSL ChaCha20");
    final sslKey = Uint8List(32);
    final sslIv  = Uint8List(16); // EVP_chacha20: 4-byte counter + 12-byte nonce
    _fillRandom(sslKey);
    _fillRandom(sslIv);
    _warmup(warmups, () {
      final enc = openssl.chacha20Encrypt(inputBytes, sslKey, sslIv);
      openssl.chacha20Decrypt(enc, sslKey, sslIv);
    });
    count = 0;
    sw..reset()..start();
    while (count < repeat) {
      final enc = openssl.chacha20Encrypt(inputBytes, sslKey, sslIv);
      final dec = openssl.chacha20Decrypt(enc, sslKey, sslIv);
      stdout.write(const ListEquality().equals(dec, inputBytes)
          ? chalk.green(".") : chalk.red("."));
      count++;
    }
    sw.stop();
    var opensslMs = sw.elapsedMilliseconds;
    mbps = _mbps(inputBytes.length, repeat, opensslMs);
    print("\n$opensslMs ms  ${chalk.green('$mbps')} mbps");
    pct = opensslMs == 0 ? 0 : ((pcMs / opensslMs) * 100).round() - 100;
    print(pct > 0
        ? "OpenSSL faster than PC: ${chalk.green("$pct")}%"
        : "PointyCastle faster than OpenSSL: ${chalk.green("${-pct}")}%");
    results.add(TestResult('OpenSSL ChaCha20', mbps, opensslMs));
  }

  return results;
}

// ---------------------------------------------------------------------------
// libsodium tests
// ---------------------------------------------------------------------------

String getLibsodiumPath() {
  if (Platform.isMacOS) {
    for (var p in [
      '/opt/homebrew/opt/libsodium/lib/libsodium.dylib',
      '/usr/local/opt/libsodium/lib/libsodium.dylib',
    ]) {
      if (File(p).existsSync()) return p;
    }
    return 'libsodium.dylib';
  } else if (Platform.isLinux) {
    for (var p in [
      '/usr/lib/x86_64-linux-gnu/libsodium.so.23',
      '/usr/lib/x86_64-linux-gnu/libsodium.so',
      '/usr/lib/aarch64-linux-gnu/libsodium.so.23',
      '/usr/lib/aarch64-linux-gnu/libsodium.so',
      '/usr/lib/libsodium.so.23',
      '/usr/lib/libsodium.so',
      '/usr/local/lib/libsodium.so.23',
      '/usr/local/lib/libsodium.so',
    ]) {
      if (File(p).existsSync()) return p;
    }
    return 'libsodium.so';
  } else if (Platform.isWindows) {
    return 'libsodium.dll';
  }
  return 'libsodium';
}

Future<List<TestResult>> sodiumTest(
  String text,
  Uint8List inputBytes,
  int repeat,
) async {
  List<TestResult> results = [];
  final warmups = min(2, repeat);
  line();
  print("String length: ${(inputBytes.length / 1024).toStringAsFixed(0)} KB");

  try {
    final libsodiumPath = getLibsodiumPath();
    print("Loading libsodium from: $libsodiumPath");
    final sodium = await SodiumInit.init2(() => DynamicLibrary.open(libsodiumPath));

    // Correctness smoke-test before any timing.
    final testMsg   = utf8.encode("test");
    final testNonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final testKey   = sodium.crypto.secretBox.keygen();
    final testEnc   = sodium.crypto.secretBox.easy(message: testMsg, nonce: testNonce, key: testKey);
    final testDec   = sodium.crypto.secretBox.openEasy(cipherText: testEnc, nonce: testNonce, key: testKey);
    if (!const ListEquality().equals(testMsg, testDec)) {
      print(chalk.red('Sodium basic test failed'));
      testKey.dispose();
      return results;
    }
    testKey.dispose();

    // --- XSalsa20-Poly1305 ---
    line();
    print("Start Sodium XSalsa20-Poly1305");
    var key = sodium.crypto.secretBox.keygen();
    // Warmup
    for (var i = 0; i < warmups; i++) {
      final n   = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
      final enc = sodium.crypto.secretBox.easy(message: inputBytes, nonce: n, key: key);
      sodium.crypto.secretBox.openEasy(cipherText: enc, nonce: n, key: key);
    }
    int count = 0;
    final sw = Stopwatch()..start();
    while (count < repeat) {
      final n   = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
      final enc = sodium.crypto.secretBox.easy(message: inputBytes, nonce: n, key: key);
      final dec = sodium.crypto.secretBox.openEasy(cipherText: enc, nonce: n, key: key);
      stdout.write(const ListEquality().equals(dec, inputBytes)
          ? chalk.green(".") : chalk.red("."));
      count++;
    }
    key.dispose();
    sw.stop();
    var ms   = sw.elapsedMilliseconds;
    var mbps = _mbps(inputBytes.length, repeat, ms);
    print("\n$ms ms  ${chalk.green('$mbps')} mbps");
    results.add(TestResult('Sodium XSalsa20-Poly1305', mbps, ms));

    // --- ChaCha20-Poly1305 AEAD ---
    line();
    print("Start Sodium ChaCha20-Poly1305 AEAD");
    var aeadKey = sodium.crypto.aead.keygen();
    // Warmup
    for (var i = 0; i < warmups; i++) {
      final n   = sodium.randombytes.buf(sodium.crypto.aead.nonceBytes);
      final enc = sodium.crypto.aead.encrypt(message: inputBytes, nonce: n, key: aeadKey);
      sodium.crypto.aead.decrypt(cipherText: enc, nonce: n, key: aeadKey);
    }
    count = 0;
    sw..reset()..start();
    while (count < repeat) {
      final n   = sodium.randombytes.buf(sodium.crypto.aead.nonceBytes);
      final enc = sodium.crypto.aead.encrypt(message: inputBytes, nonce: n, key: aeadKey);
      final dec = sodium.crypto.aead.decrypt(cipherText: enc, nonce: n, key: aeadKey);
      stdout.write(const ListEquality().equals(dec, inputBytes)
          ? chalk.green(".") : chalk.red("."));
      count++;
    }
    aeadKey.dispose();
    sw.stop();
    ms   = sw.elapsedMilliseconds;
    mbps = _mbps(inputBytes.length, repeat, ms);
    print("\n$ms ms  ${chalk.green('$mbps')} mbps");
    results.add(TestResult('Sodium ChaCha20-Poly1305 AEAD', mbps, ms));

  } catch (e) {
    print(chalk.red('Sodium error: $e'));
    if (e.toString().contains('cannot open shared object') ||
        e.toString().contains('Failed to load dynamic library')) {
      print(chalk.yellow('libsodium not found – install it:'));
      if (Platform.isLinux) {
        print(chalk.yellow('  Ubuntu/Debian: sudo apt-get install libsodium23'));
      } else if (Platform.isMacOS) {
        print(chalk.yellow('  macOS: brew install libsodium'));
      }
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// FastCrypt (string API only – no bytes path available)
// ---------------------------------------------------------------------------

List<TestResult> fastcryptTest(String text, int repeat) {
  List<TestResult> results = [];
  line();
  print("String length: ${(text.length / 1024).toStringAsFixed(0)} KB");

  try {
    var fc = FastCrypt();
    // Smoke-test
    final testEnc = fc.encryptString("test");
    final t = fc.decryptString(
      ciphertext: testEnc.ciphertext,
      tag: testEnc.tag,
      key: testEnc.key,
      nonce: testEnc.nonce,
    );
    if (t != "test") {
      print(chalk.red('FastCrypt basic test failed'));
      return results;
    }

    // Warmup
    final warmups = min(2, repeat);
    for (var i = 0; i < warmups; i++) {
      final enc = fc.encryptString(text);
      fc.decryptString(ciphertext: enc.ciphertext, tag: enc.tag, key: enc.key, nonce: enc.nonce);
    }

    line();
    print("Start FastCrypt ChaCha20-Poly1305");
    int count = 0;
    final sw = Stopwatch()..start();
    while (count < repeat) {
      final enc = fc.encryptString(text);
      final dec = fc.decryptString(ciphertext: enc.ciphertext, tag: enc.tag, key: enc.key, nonce: enc.nonce);
      stdout.write(dec == text ? chalk.green(".") : chalk.red("."));
      count++;
    }
    sw.stop();
    var ms   = sw.elapsedMilliseconds;
    var mbps = _mbps(text.length, repeat, ms);
    print("\n$ms ms  ${chalk.green('$mbps')} mbps");
    results.add(TestResult('FastCrypt ChaCha20-Poly1305', mbps, ms));
  } catch (e) {
    print(chalk.red('FastCrypt error: $e'));
  }
  return results;
}

// ---------------------------------------------------------------------------
// OpenSSL package tests — naive (Arena-per-call) vs optimised (persistent ctx)
// ---------------------------------------------------------------------------

List<TestResult> opensslPkgTest(
  Uint8List inputBytes,
  int repeat, {
  required OpenSslPkgCrypto pkgCrypto,
}) {
  List<TestResult> results = [];
  final warmups = min(2, repeat);

  final aesKey = Uint8List(32);
  final aesIv  = Uint8List(16);
  _fillRandom(aesKey);
  _fillRandom(aesIv);

  final chaKey = Uint8List(32);
  final chaIv  = Uint8List(16);
  _fillRandom(chaKey);
  _fillRandom(chaIv);

  // --- SHA-256 naive ---
  line();
  print("Start OpenSSL pkg SHA256 (naive)");
  _warmup(warmups, () => opensslPkgSha256(inputBytes));
  int count = 0;
  final sw = Stopwatch()..start();
  while (count < repeat) {
    opensslPkgSha256(inputBytes);
    stdout.write('.');
    count++;
  }
  sw.stop();
  var ms   = sw.elapsedMilliseconds;
  var mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg SHA256 naive', mbps, ms));

  // --- SHA-256 optimised ---
  line();
  print("Start OpenSSL pkg SHA256 (optimised)");
  _warmup(warmups, () => pkgCrypto.sha256(inputBytes));
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    pkgCrypto.sha256(inputBytes);
    stdout.write('.');
    count++;
  }
  sw.stop();
  ms   = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg SHA256 opt', mbps, ms));

  // --- AES-256-CTR naive ---
  line();
  print("Start OpenSSL pkg AES-256-CTR (naive)");
  _warmup(warmups, () {
    final enc = opensslPkgAes256CtrEncrypt(inputBytes, aesKey, aesIv);
    opensslPkgAes256CtrDecrypt(enc, aesKey, aesIv);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final enc = opensslPkgAes256CtrEncrypt(inputBytes, aesKey, aesIv);
    final dec = opensslPkgAes256CtrDecrypt(enc, aesKey, aesIv);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  ms   = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg AES-CTR naive', mbps, ms));

  // --- AES-256-CTR optimised ---
  line();
  print("Start OpenSSL pkg AES-256-CTR (optimised)");
  _warmup(warmups, () {
    final enc = pkgCrypto.aes256CtrEncrypt(inputBytes, aesKey, aesIv);
    pkgCrypto.aes256CtrDecrypt(enc, aesKey, aesIv);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final enc = pkgCrypto.aes256CtrEncrypt(inputBytes, aesKey, aesIv);
    final dec = pkgCrypto.aes256CtrDecrypt(enc, aesKey, aesIv);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  ms   = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg AES-CTR opt', mbps, ms));

  // --- ChaCha20 naive ---
  line();
  print("Start OpenSSL pkg ChaCha20 (naive)");
  _warmup(warmups, () {
    final enc = opensslPkgChacha20Encrypt(inputBytes, chaKey, chaIv);
    opensslPkgChacha20Decrypt(enc, chaKey, chaIv);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final enc = opensslPkgChacha20Encrypt(inputBytes, chaKey, chaIv);
    final dec = opensslPkgChacha20Decrypt(enc, chaKey, chaIv);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  ms   = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg ChaCha20 naive', mbps, ms));

  // --- ChaCha20 optimised ---
  line();
  print("Start OpenSSL pkg ChaCha20 (optimised)");
  _warmup(warmups, () {
    final enc = pkgCrypto.chacha20Encrypt(inputBytes, chaKey, chaIv);
    pkgCrypto.chacha20Decrypt(enc, chaKey, chaIv);
  });
  count = 0;
  sw..reset()..start();
  while (count < repeat) {
    final enc = pkgCrypto.chacha20Encrypt(inputBytes, chaKey, chaIv);
    final dec = pkgCrypto.chacha20Decrypt(enc, chaKey, chaIv);
    stdout.write(const ListEquality().equals(dec, inputBytes)
        ? chalk.green(".") : chalk.red("."));
    count++;
  }
  sw.stop();
  ms   = sw.elapsedMilliseconds;
  mbps = _mbps(inputBytes.length, repeat, ms);
  print("\n$ms ms  ${chalk.green('$mbps')} mbps");
  results.add(TestResult('OpenSSL pkg ChaCha20 opt', mbps, ms));

  return results;
}

// ---------------------------------------------------------------------------

const _chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
Random _rnd = Random();

String getRandomString(int length) => String.fromCharCodes(Iterable.generate(
    length, (_) => _chars.codeUnitAt(_rnd.nextInt(_chars.length))));
