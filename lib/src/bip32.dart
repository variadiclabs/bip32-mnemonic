import 'dart:convert';
import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart' hide State;
// ignore: implementation_imports
import 'package:pointycastle/src/utils.dart' as util;
import 'package:secp256k1/secp256k1.dart' as lib_secp256k1;
import 'package:web3dart/web3dart.dart';

// this implementation is based heavily on https://github.com/vergl4s/ethereum-mnemonic-utils/blob/master/mnemonic_utils.py
// which derives from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py

/// An implementation for deriving keys from a BIP32 mnemonic given an HD derivation path
class BIP32 {

  /// Derive a public key from the private key
  Uint8List _derivePublicKey(Uint8List privateKey) {
    final String publicKey =
        lib_secp256k1.PrivateKey.fromHex(hex.encode(privateKey))
            .publicKey
            .toCompressedHex();
    return Uint8List.fromList(hex.decoder.convert(publicKey));
  }

  /// Derive a BIP32 child key
  List<Uint8List> _deriveBip32ChildKey(
      Uint8List parentKey, Uint8List parentChain, BigInt i) {
    Uint8List childKey;
    Uint8List childChain;
    final BigInt curveInt = ECCurve_secp256k1().n;
    final Uint8List k = parentChain;
    bool hasOffset = true;
    if (i >= BigInt.from(2147483648)) {
      childKey = parentKey;
    } else {
      childKey = _derivePublicKey(parentKey);
      hasOffset = false;
    }
    final Uint8List msg = Uint8List(37);

    final ByteData suffix = ByteData(4);
    suffix.setInt32(0, int.parse(i.toString()));

    if (hasOffset) {
      msg[0] = 0;
      final Uint8List encodedLen = Uint8List(32);
      encodedLen.setAll(encodedLen.length - childKey.length, childKey);
      msg.setAll(1, encodedLen);
    } else {
      final Uint8List encodedLen = Uint8List(33);
      encodedLen.setAll(encodedLen.length - childKey.length, childKey);
      msg.setAll(0, encodedLen);
    }

    msg.setAll(33, suffix.buffer.asUint8List());

    while (true) {
      final Uint8List h =
          (HMac(SHA512Digest(), 128)..init(KeyParameter(k))).process(msg);
      childKey = h.sublist(0, 32);
      childChain = h.sublist(32);
      final BigInt a = util.decodeBigIntWithSign(1, childKey);
      final BigInt b = util.decodeBigIntWithSign(1, parentKey);
      childKey = util.encodeBigIntAsUnsigned((a + b) % curveInt);
      if (a < curveInt && ((a + b) % curveInt != BigInt.from(0))) {
        break;
      }
      msg[0] = 1;
      msg.setAll(1, childChain);
      msg.setAll(33, suffix.buffer.asUint8List());
    }

    return <Uint8List>[childKey, childChain];
  }

  /// Returns a raw hex-encoded string for a given mnemonic
  String derivePrivateKeyFromMnemonic(String mnemonic, String derivationPath,
      [int change = 0, int addressIndex = 0]) {
    assert(derivationPath.substring(0, 2) == 'm/');
    final List<String> derivationPathSplit =
        derivationPath.substring(2).split('/');
    final List<BigInt> derivationPathLst = [];
    // ignore: avoid_function_literals_in_foreach_calls
    derivationPathSplit.forEach((String indivComponent) {
      if (indivComponent.contains('\'')) {
        derivationPathLst.add(BigInt.from(
            2147483648 + int.parse(indivComponent.replaceAll('\'', ''))));
      } else {
        derivationPathLst.add(BigInt.from(int.parse(indivComponent)));
      }
    });

    final Uint8List seed = bip39.mnemonicToSeed(mnemonic);

    final Uint8List hash = (HMac(SHA512Digest(), 128)
          ..init(KeyParameter(utf8.encoder.convert('Bitcoin seed'))))
        .process(seed);
    Uint8List key = hash.sublist(0, 32);
    Uint8List chain = hash.sublist(32);

    // ignore: avoid_function_literals_in_foreach_calls
    derivationPathLst.forEach((BigInt path) {
      final List<Uint8List> keyAndChain =
          _deriveBip32ChildKey(key, chain, path);
      key = keyAndChain[0];
      chain = keyAndChain[1];
    });

    return hex.encode(key);
  }

  /// Return a web3dart Credentials object from a private key
  Future<Credentials> deriveCredentialsFromPrivateKey(String privKey) async {
    return EthPrivateKey.fromHex(privKey);
  }

  /// Return a signed message given a web3dart Credentials object and a message
  Future<String> signWithEthereumAddress(
      Credentials credentials, String dataToSign) async {
    final Uint8List signedMsg = await credentials
        .signPersonalMessage(Uint8List.fromList(utf8.encode(dataToSign)));
    return hex.encode(signedMsg);
  }
}
