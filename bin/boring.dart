import 'package:boring/boring.dart' as boring;
import 'dart:typed_data';
import 'dart:convert' show utf8;

import 'package:hex/hex.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:crypto/crypto.dart' as crypto;
import 'package:better_cryptography/better_cryptography.dart' as better;

Future<void> main() async {
  final String plainText = "Hello World";
  final digest = crypto.sha256.convert(utf8.encode(plainText));
  print("SHA256 of : $plainText");
  print(HEX.encode(digest.bytes));

  // AES-256-CTR using package:encrypt
  final key = encrypt.Key.fromUtf8('my 32 length key................');
  final iv  = encrypt.IV.fromUtf8('my 16 length key');
  final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.ctr));
  final c = encrypter.encryptBytes(utf8.encode(plainText), iv: iv);

  print("AES256 CTR mode of : $plainText");
  print(HEX.encode(c.bytes));

  final dec = encrypter.decryptBytes(c, iv: iv);
  print("Decrypted (encrypt pkg): ${utf8.decode(dec)}");

  // Cross-check with better_cryptography
  final bAlgorithm = better.AesCtr.with256bits(macAlgorithm: better.MacAlgorithm.empty);
  final bSecretKey = await bAlgorithm.newSecretKeyFromBytes(
      utf8.encode('my 32 length key................'));
  final bSec = better.SecretBox(c.bytes, nonce: iv.bytes, mac: better.Mac.empty);
  final bClear = await bAlgorithm.decrypt(bSec, secretKey: bSecretKey);
  print('Decoded by better_cryptography: ${utf8.decode(bClear)}');

  // Demonstrate OpenSSL FFI if available
  try {
    final openssl = boring.OpenSslCrypto(boring.getOpenSslLibPath());
    final hash = openssl.sha256(Uint8List.fromList(utf8.encode(plainText)));
    print('OpenSSL SHA256: ${HEX.encode(hash)}');
    openssl.dispose();
  } catch (e) {
    print('OpenSSL unavailable: $e');
  }
}
