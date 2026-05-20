import 'package:boring/boring.dart' as boring;
import 'dart:typed_data';
import 'dart:convert' show base64, utf8;
import 'package:hex/hex.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

import 'package:webcrypto/webcrypto.dart' as webcrypto;
import 'package:cryptography/cryptography.dart' as crypto;

import 'package:better_cryptography/better_cryptography.dart' as better;

Future<void> main() async {
  final String plainText = "Hello World";
  final digest =
      await webcrypto.Hash.sha256.digestBytes(utf8.encode(plainText));
  var sha256 = HEX.encode(digest);
  print("SHA256 of : $plainText");
  print(sha256);

  // Generate a new random AES-CTR secret key for AES-256.
  //final k = await AesCtrSecretKey.generateKey(256);
  final k = await webcrypto.AesCtrSecretKey.importRawKey(
      Uint8List.fromList(utf8.encode('my 32 length key................')));

// Use a unique counter for each message.
  // final ctr = Uint8List(16); // always 16 bytes
  // fillRandomBytes(ctr);
  final ctr = Uint8List.fromList(utf8.encode('my 16 length key'));

// Length of the counter, the N'th right most bits of ctr are incremented
// for each block, the left most 128 - N bits are used as static nonce.
// Thus, messages must be less than 2^64 * 16 bytes.
  final N = 64;

// Encrypt a message
  final c = await k.encryptBytes(utf8.encode(plainText), ctr, N);

  print("AES256 CTR mode of : $plainText");
  print(HEX.encode(c));

// Decrypt message (requires the same counter ctr and length N)
  print(
      "BoringSSL Decrypted: ${utf8.decode(await k.decryptBytes(c, ctr, N))}"); // hello world

//Decrypt with Crypt Lib too
  final key = utf8.encode('my 32 length key................');
  final iv = utf8.encode('my 16 length key');
  var algorithm =
      crypto.AesCtr.with256bits(macAlgorithm: crypto.MacAlgorithm.empty);
  final secretKey = await algorithm.newSecretKeyFromBytes(key);
  var sec = crypto.SecretBox(c, nonce: iv, mac: crypto.Mac.empty);
  //algorithm.newNonce();
  final clearText = await algorithm.decrypt(
    sec,
    secretKey: secretKey,
  );
  print('Decoded by cryptography software: ${utf8.decode(clearText)}');

  var bAlgorithm =
      better.AesCtr.with256bits(macAlgorithm: better.MacAlgorithm.empty);
  var bsecretKey = await bAlgorithm.newSecretKeyFromBytes(key);
  var bSec = better.SecretBox(c, nonce: iv, mac: better.Mac.empty);
  var bClearText = await bAlgorithm.decrypt(bSec, secretKey: bsecretKey);

    print('Decoded by better cryptography software: ${utf8.decode(bClearText)}');

}
