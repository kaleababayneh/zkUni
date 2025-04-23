

const { Wallet } = require('@ethereumjs/wallet')
const { randomBytes } = require('crypto');
const BN = require('bn.js');

const maxValue = new BN('1000000000000000000000000000000000000000000000000000000000000000', 16); // Example l-1
let privateKey;
do {
  privateKey = new BN(randomBytes(32));
} while (privateKey.gte(maxValue));

const wallet = Wallet.fromPrivateKey(Buffer.from(privateKey.toString(16).padStart(64, '0'), 'hex'));
console.log('Private Key:', wallet.getPrivateKeyString());
console.log('Address:', wallet.getAddressString());