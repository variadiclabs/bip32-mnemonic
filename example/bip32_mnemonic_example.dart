import 'package:bip32_mnemonic/bip32_mnemonic.dart';
import 'package:web3dart/web3dart.dart';

void main() async {
  BIP32 bip32 = BIP32();

  // random seed phrase with checksum. DO NOT use this in production/send funds to it!
  final String mnemonic = "twelve destroy arena gain dismiss punch obscure history achieve castle drill silver";
  final String messageToBeSigned = "some test message";

  // outputs dfc6438d86d0c43e0f65b9eb46a9c618ae49435d3d1fe8469893423932f7af46
  final String privKey = bip32.derivePrivateKeyFromMnemonic(mnemonic, "m/44'/60'/0'/0/0'");
  
  // generates web3dart Credentials object
  final Credentials creds = await bip32.deriveCredentialsFromPrivateKey(privKey);

  // outputs 36fa46f8ca704da17fcb5a4f2b4891438f777233eced45f488fb98923036956956ee84edc041972980c6a755fd5372bf546d31f562ccc4f00fe3a99a77d205971c
  final String signedMessage = await bip32.signWithEthereumAddress(creds, messageToBeSigned);

  print(signedMessage);
}
