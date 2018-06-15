const crypto = require('crypto');
const shamir = require('../shamir');

let secret = process.argv[2];
let shares = process.argv[3];
let threshold = process.argv[4];

if (!secret || !shares || !threshold) {
  return console.log(`Usage:\n./generateShares.js '<my super secret data>' <shareCount> <thresholdCount>`);
}

shares = parseInt(shares);
threshold = parseInt(threshold);

if (isNaN(shares) || shares <= 0) {
  return console.log('Shares must be an integer greater than 0');
}

if (typeof threshold !== 'number' || threshold <= 0 || threshold > shares) {
  return console.log('Threshold must be an integer greater than 0 and less than the number of shares');
}

let hexSecret = Buffer.from(secret).toString('hex');
let checksum = crypto.createHash('sha256').update(hexSecret).digest('hex').substr(56);
let checkedHexSecret = hexSecret + checksum;

console.log(shamir.generateShares(checkedHexSecret, shares, threshold));
