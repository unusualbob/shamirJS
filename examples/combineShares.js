const crypto = require('crypto');
const shamir = require('../shamir');

let shares = process.argv.slice(2);

if (!shares || !shares.length || shares.length < 2) {
  return console.log(`Usage:\n./combineShares.js <share1> <share2> <share3> ...\n You must have the minimum threshold of shares or output will be garbage`);
}

let checkedHexSecret = shamir.deriveSecret(shares);

let hexSecret = checkedHexSecret.substr(0, checkedHexSecret.length - 8);
let storedChecksum = checkedHexSecret.substr(-8);

let derivedChecksum = crypto.createHash('sha256').update(hexSecret).digest('hex').substr(56);

if (derivedChecksum !== storedChecksum) {
  return console.log('Checksum did not match, likely invalid or not enough keys');
}

let secret = Buffer.from(hexSecret, 'hex').toString('utf8');
console.log('Derived secret', secret);
