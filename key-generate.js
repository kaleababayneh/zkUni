const { randomBytes } = require('crypto');
const BN = require('bn.js');
const { ec: EC } = require('elliptic');

const ec = new EC('secp256k1');

// Scalar field limit (can be changed for circuit constraints, here set to 2^255)
const maxValue = new BN('1000000000000000000000000000000000000000000000000000000000000000', 16); // 2^255

function generateElGamalKeyWithLeadingZero(maxAttempts = 100000) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    // Ensure private key is within desired field limit
    let privKeyBN;
    do {
      privKeyBN = new BN(randomBytes(32));
    } while (privKeyBN.gte(maxValue));

    const privateKeyHex = privKeyBN.toString('hex').padStart(64, '0');

    // Derive public key
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');
    const publicKey = keyPair.getPublic();
    const xHex = publicKey.getX().toString('hex');

    if (xHex.startsWith('0')) {
      console.log(`🎯 Found matching key on attempt ${attempt}`);
      return {
        privateKey: privateKeyHex,
        publicKeyX: xHex,
        publicKeyY: publicKey.getY().toString('hex')
      };
    }

    if (attempt % 10000 === 0) {
      console.log(`Tried ${attempt} keys... still searching.`);
    }
  }

  throw new Error("⚠️ Couldn't find a matching key.");
}

function exportForNoir(keyPair) {
  return {
    privateKey: `0x${keyPair.privateKey}`,
    publicKey: {
      x: `0x${keyPair.publicKeyX}`,
      y: `0x${keyPair.publicKeyY}`
    }
  };
}

// Generate and export
const keyPair = generateElGamalKeyWithLeadingZero();
const studentKey = exportForNoir(keyPair);

console.log("\n✅ Generated Key for Noir:");
console.log(JSON.stringify(studentKey, null, 2));
