import 'dart:typed_data';

import 'package:bip32_mnemonic/bip32_mnemonic.dart';
import 'package:test/test.dart';
import 'package:web3dart/credentials.dart';

void main() {

  // these mnemonics exist only for testing purposes. DO NOT use them in production/with funds!
  String mnemonic = "mad valley dry text citizen grain casino solid sorry kangaroo bench finish";
  String mnemonic24 = "follow rhythm tired truly voyage invite finger swing analyst gesture popular poet point purpose injury endorse knee model express script main stool invite man";

  group('Deriving private key from 12 word mnemonic via derivation path', () {
    
    BIP32 bip32 = BIP32();

    test("m/44'/60'/0'/0/0", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic, 'm/44\'/60\'/0\'/0/0'), matches("36011ce4d10f9a84a183d723bee7936d17c051137ab82538db0b9d21adeb4248"));
    });

    test("m/44'/60'/0'/0/1", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic, 'm/44\'/60\'/0\'/0/1'), matches("30d543c997f3cbcd9051574fe8cfece2c733e949b00c31a7624d003f0fbe46dc"));
    });

    test("m/44'/60'/0'/1/1", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic, 'm/44\'/60\'/0\'/1/1'), matches("54da3b31dfad193bc38d657f38edf1bc3dcf6c355c9351232ea2f85f07733513"));
    });

    test("m/44'/60'/0'/1/1'", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic, 'm/44\'/60\'/0\'/1/1\''), matches("9f250886e73fa67824c99044220bbb6fa4e28f12d346db8c240d3fd5fb90ac7a"));
    });

    test("m/44'/60'/1'/1/1'", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic, 'm/44\'/60\'/1\'/1/1\''), matches("5b4c2365f2f5b9c15204b85f7a1d89d7c801a6203d3067ad11c718229991c9ac"));
    });
  });

  group('Deriving private key from 24 word mnemonic via derivation path', () {
    
    BIP32 bip32 = BIP32();

    test("m/44'/60'/0'/0/0", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic24, 'm/44\'/60\'/0\'/0/0'), matches("cc4c76f89382ad83568399fd7815534e1da1aaf5260967cff0bdb01bbf578670"));
    });

    test("m/44'/60'/0'/0/1", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic24, 'm/44\'/60\'/0\'/0/1'), matches("d689c83c6a4dc6cb27f87b09ab7e9a01655160fea85a6a391edd130260c517a6"));
    });

    test("m/44'/60'/0'/1/1", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic24, 'm/44\'/60\'/0\'/1/1'), matches("9b78712c10e214997ebeedd74699d2f623e6111d96d4d98ba63c18ab097b51c3"));
    });

    test("m/44'/60'/0'/1/1'", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic24, 'm/44\'/60\'/0\'/1/1\''), matches("4e317f9e37a0135d69fb76b247380dbdd3bbcc01f667c67dc233131c974b7372"));
    });

    test("m/44'/60'/1'/1/1'", () {
      expect(bip32.derivePrivateKeyFromMnemonic(mnemonic24, 'm/44\'/60\'/1\'/1/1\''), matches("68708d306d71f6bda1fa3e46aafe5bd90c6f20d36cde8dc4b54dde5a77556abe"));
    });
  });

  group('Derive Credentials from private key and sign message', () {
    BIP32 bip32 = BIP32();
    Credentials creds = EthPrivateKey(Uint8List(0));
    setUp(() async {
      creds = await bip32.deriveCredentialsFromPrivateKey("36011ce4d10f9a84a183d723bee7936d17c051137ab82538db0b9d21adeb4248");
    });

    test("FOOBAR", () async {
      expect(await bip32.signWithEthereumAddress(creds, "FOOBAR"), matches("bd6cf4819ca031a20edba64f906abf8d9f9444a4fc6ee8419bcdf958f6a3ce4f34038e6bca2715fdd292f6c7c05fc0a6a9ca2e2ca8bbf675e612a2369914bc811b"));
    });
  });
}
