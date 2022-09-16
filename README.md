<!-- 
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages). 

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages). 
-->

A BIP32 implementation for generating public/private key pairs from a mnemonic seed phrase, given an HD derivation path.

## Features

Generate public/private key pairs from a mnemonic, using the BIP32 derivation path. Derives both hardened and non-hardened addresses following the `m/44'` derivation path format.

## Usage

Generate a public/private key pair:

```dart
BIP32 bip32 = BIP32();

// returns a private key without the leading 0x prefix as a String
// given an HD derivation path and mnemonic seed phrase
String privKey = bip32.derivePrivateKeyFromMnemonic(
  mnemonic,
  "m/44'/60'/0'/0/0"
);

// helper function for creating a web3dart Credentials object for operations e.g. signing
Credentials creds = await bip32.deriveCredentialsFromPrivateKey(privKey);
```

## Feature Requests

Please file feature requests and bugs on Github [here](https://github.com/variadiclabs/bip32-mnemonic/issues/new).
