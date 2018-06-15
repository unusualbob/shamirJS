const crypto = require('crypto');

const fieldBits = 8; // number of bits to use, GF(2^8)
const maxShares = 255; //2^8 - 1

// We generate these logarithm and exponent lookup tables since all operations happen within the Galois Field and we will
// do these calculations tens of thousands of times (or more) during this process. Much faster to lookup this data.
const calculatedLogarithms = [];
const calculatedExponents = [];

let x = 1;
for (let i = 0; i < 256; i++) {
  calculatedExponents[i] = x;
  calculatedLogarithms[x] = i;
  x = x << 1;
  if (x & 256) {
    // 0x11d is the value used for GF(2^8) to keep values within the field
    // it is calculated from (x^8 + x^4 + x^3 + x^2 + 1)
    x ^= Number('0x11d');
  }
}

//Simple string of zeroes used later for padding
let zeroPadding = new Array(1024).join('0');

const helpers = {
  strings: {
    /**
     * Converts a hexadecimal string into a binary string
     * @param hexString {string} Hexadecimal string, ie 'a1cd4f'
     * @returns {String} Binary string, ie '1010011011'
     */
    hexadecimalToBinary: function(hexString) {
      let binaryString = '';

      for (let i = hexString.length - 1; i >= 0; i--) {
        let num = parseInt(hexString[i], 16);

        if (isNaN(num)) {
          throw new Error('Invalid hex character.');
        }

        binaryString = helpers.strings.padLeft(num.toString(2), 4) + binaryString;
      }
      return binaryString;
    },
    /**
     * Converts a binary string into a hexadecimal string
     * @param binaryString {String} Binary string, ie '1010011011'
     * @returns {string} Hexadecimal string, ie 'a1cd4f'
     */
    binaryToHexadecimal: function(binaryString) {
      let hexadecimalString = '';

      binaryString = helpers.strings.padLeft(binaryString, 4);

      for (let i = binaryString.length; i >= 4; i -= 4) {
        let num = parseInt(binaryString.slice(i - 4, i), 2);
        if (isNaN(num)) {
          throw new Error('Invalid binary character.');
        }
        hexadecimalString = num.toString(16) + hexadecimalString;
      }

      return hexadecimalString;
    },
    /**
     * Pads a given string with zeroes on the left so that its length is a multiple of `multipleOfBits`
     * ex. ('1001', 7) -> 0001001
     * ex. ('11010', 4) -> 00011010
     * ex. ('10', 10) -> 0000000010
     * @param stringToPad {String} String to left-pad
     * @param multipleOfBits {Number} Value of which the output must be multiple, defaults to fieldBits if not provided
     * @returns {String} Padded string
     */
    padLeft: function(stringToPad, multipleOfBits = fieldBits) {
      let bitsToPad;

      if (multipleOfBits === 0 || multipleOfBits === 1) {
        return stringToPad;
      }

      if (multipleOfBits && multipleOfBits > 1024) {
        throw new Error('Padding must be multiples of no larger than 1024 bits.');
      }

      if (stringToPad) {
        bitsToPad = stringToPad.length % multipleOfBits;
      }

      if (bitsToPad) {
        return (zeroPadding + stringToPad).slice(-(multipleOfBits - bitsToPad + stringToPad.length));
      }

      return stringToPad;
    },

    /**
     * If a `padLength` is included this zero-pads the input string to have a length to be a multiple of `padLength`. It then splits the
     * provided string of numbers into 8 bit length sections. It returns an array of integers wherein each element represents an 8 bit
     * length section of the original input string. The output data is in reverse order, meaning that parts[0] represents the last 8 bits
     * of the original input string
     * @param stringToSplit {String} Binary string which should be converted into integers
     * @param padLength [Number] How much to pad the input string
     * @returns {Number[]} Array of integers equivalent to the binary when parsed in 8 bit sections
     */
    splitNumStringToIntArray: function(stringToSplit, padLength) {
      let parts = [];
      let i;

      if (padLength) {
        stringToSplit = helpers.strings.padLeft(stringToSplit, padLength);
      }

      for (i = stringToSplit.length; i > fieldBits; i -= fieldBits) {
        parts.push(parseInt(stringToSplit.slice(i - fieldBits, i), 2));
      }

      parts.push(parseInt(stringToSplit.slice(0, i), 2));

      return parts;
    }
  },
  shareOperations: {
    /**
     * Given a public share, extract the bits (Integer), share ID (Integer), and share data (Hex)
     * and return an Object containing those components.
     * @param share {String}
     * @returns {object}
     */
    extractShareComponents: function(share) {
      let id;

      // Extract each part of the share
      let shareComponents = /^([a-fA-F\d]{2})([a-fA-F\d]+)$/.exec(share);

      // The ID is a Hex number and needs to be converted to an Integer
      if (shareComponents) {
        id = parseInt(shareComponents[1], 16);
      }

      if (typeof id !== 'number' || id % 1 !== 0 || id < 1 || id > maxShares) {
        throw new Error(`Invalid share : Share id must be an integer between 1 and ${maxShares}, inclusive.`);
      }

      if (shareComponents && shareComponents[2]) {
        return {
          id: id,
          data: shareComponents[2]
        };
      }

      throw new Error(`The share data provided is invalid : ${share}`);
    },

    /**
     * This generates a randomized polynomial function where f(0) = secret, and then returns `totalShares` of coordinate
     * pairs from that line, of which `requiredShares` are required to reconstruct `secret`. If the input secret is greater than 2 ^ fieldBits
     * then the output will be incorrect as we do not check the value here
     *
     * @param secret {Number} Number you want to be hidden
     * @param totalShares {Number} Number of shares you want to generate
     * @param requiredShares {Number} Number of shares necessary to reconstruct the secret number
     * @returns {Object[]} Array of objects which are X and Y coordinates
     */
    calculateRandomizedShares: function (secret, totalShares, requiredShares) {
      let shares = [];
      let coefficients = [secret];

      // Pick random coefficients for our polynomial function
      for (let i = 1; i < requiredShares; i++) {
        coefficients[i] = parseInt(helpers.crypto.getRandomBinaryString(fieldBits), 2);
      }

      // Calculate the y value of each share based on f(x) when using our new random polynomial function
      for (let i = 1, len = totalShares + 1; i < len; i++) {
        shares[i - 1] = {
          x: i,
          y: helpers.crypto.calculateFofX(i, coefficients)
        };
      }

      return shares;
    }
  },
  crypto: {
    /**
     * Given some coefficients representing a polynomial function, this calculates the value f(x)
     * @param x {Number} Integer position
     * @param coefficients
     * @returns {number}
     */
    calculateFofX: function(x, coefficients) {
      const logX = calculatedLogarithms[x];
      let fx = 0;

      for (let i = coefficients.length - 1; i >= 0; i--) {
        if (fx !== 0) {
          fx = calculatedExponents[(logX + calculatedLogarithms[fx]) % maxShares] ^ coefficients[i];
        } else {
          // if f(0) then we just return the coefficient as it's just equivalent to the Y offset. Using the exponent table would result
          // in an incorrect answer
          fx = coefficients[i];
        }
      }

      return fx;
    },

    /**
     * Evaluate the Lagrange interpolation polynomial at x = 0 using x and y Arrays that are of the same length, with
     * corresponding elements constituting points on the polynomial.
     *
     * In english, this accepts an array of X and Y coordinates, it then uses them to determine what polynomial function fits all of
     * these points and then returns the value of Y where X = 0
     * @param x {Number[]} An array of X coordinates
     * @param y {Number[]} An array of Y coordinates
     * @returns {Number} Value of fx(at)
     */
    lagrange: function (x, y) {
      let sum = 0;

      for (let i = 0; i < x.length; i++) {
        if (y[i]) {

          let product = calculatedLogarithms[y[i]];

          for (let j = 0; j < x.length; j++) {
            if (i !== j) {
              product = (product + calculatedLogarithms[0 ^ x[j]] - calculatedLogarithms[x[i] ^ x[j]] + maxShares) % maxShares;
            }
          }

          // Note that undefined ^ anything = anything in Node.js
          sum = sum ^ calculatedExponents[product];
        }
      }

      return sum;
    },

    /**
     * Generates and returns a random binary string, ie 11010101
     * @param bits
     */
    getRandomBinaryString: function (bits) {
      const size = 4;
      const bytes = Math.ceil(bits / 8);
      let string = '';

      // While catch is here to regen if string is all 0's
      while (string === '') {
        let byteString = crypto.randomBytes(bytes).toString('hex');

        let i = 0;
        let len = 0;
        let parsedInt;

        if (byteString) {
          len = byteString.length - 1;
        }

        while (i < len || (string.length < bits)) {
          // convert any negative numbers to positive with Math.abs()
          parsedInt = Math.abs(parseInt(byteString[i], 16));
          string = string + helpers.strings.padLeft(parsedInt.toString(2), size);
          i++;
        }

        string = string.substr(-bits);

        // erase string so this result can be re-processed if the result is all 0's.
        if ((string.match(/0/g) || []).length === string.length) {
          string = '';
        }

      }

      return string;
    }
  }
};

let Shamir = {
  /**
   * Divides a `secret` hexadecimal string into `totalShares` shares, of which `requiredShares` number of shares are necessary to
   * reconstruct the secret. Optionally, zero-pads the secret to a length that is a multiple of `padLength` before splitting.
   * @param secret {String} Secret which is by default in hexadecimal format
   * @param totalShares {Number} The number of total shares you want to generate
   * @param requiredShares {Number} The minimum number of shares required to derive the secret
   * @param [padLength] {Number} Optional minimum length to pad the secret to, this defaults to 128
   * @returns {[String]}
   */
  generateShares: function(secret, totalShares, requiredShares, padLength) {
    let neededBits;
    let subShares;
    let x = new Array(totalShares);
    let y = new Array(totalShares);

    // To increase the security of smaller secrets we pad all data by 128 bits by default.
    padLength = padLength || 128;

    // Do some sanity checks to make sure that we can actually generate a valid output

    if (typeof secret !== 'string') {
      throw new Error('Secret must be a string.');
    }

    if (typeof totalShares !== 'number' || totalShares % 1 !== 0 || totalShares < 2) {
      throw new Error(`Number of shares must be an integer between 2 and 2^bits-1 (${maxShares}), inclusive.`);
    }

    if (totalShares > maxShares) {
      neededBits = Math.ceil(Math.log(totalShares + 1) / Math.LN2);
      throw new Error(`Number of shares must be an integer between 2 and 2^bits-1 (${maxShares}), inclusive. To create ${totalShares} shares, use at least ${neededBits} bits.`);
    }

    if (typeof requiredShares !== 'number' || requiredShares % 1 !== 0 || requiredShares < 2) {
      throw new Error(`Threshold number of shares must be an integer between 2 and 2^bits-1 (${maxShares}), inclusive.`);
    }

    if (requiredShares > maxShares) {
      neededBits = Math.ceil(Math.log(requiredShares + 1) / Math.LN2);
      throw new Error(`Threshold number of shares must be an integer between 2 and 2^bits-1 (${maxShares}), inclusive.  To use a threshold of ${requiredShares}, use at least ${neededBits} bits.`);
    }

    if (requiredShares > totalShares) {
      throw new Error(`Threshold number of shares was ${requiredShares} but must be less than or equal to the ${totalShares} shares specified as the total to generate.`);
    }

    if (typeof padLength !== 'number' || padLength % 1 !== 0 || padLength < 0 || padLength > 1024) {
      throw new Error('Zero-pad length must be an integer between 0 and 1024 inclusive.');
    }

    // Convert the secret string into a binary string, then prepend a 1 as a marker so that later we can determine where the zero padding
    // ends and the secret begins
    secret = '1' + helpers.strings.hexadecimalToBinary(secret);

    // Convert binary string into an array of integers
    secret = helpers.strings.splitNumStringToIntArray(secret, padLength);

    // For each character in the secret integer array, generate `totalShares` sub-shares, concatenating each sub-share `j` to create a total
    // of `totalShares` outputs
    for (let i = 0; i < secret.length; i++) {
      subShares = helpers.shareOperations.calculateRandomizedShares(secret[i], totalShares, requiredShares);
      for (let j = 0; j < totalShares; j++) {
        x[j] = x[j] || subShares[j].x.toString(16);
        y[j] = helpers.strings.padLeft(subShares[j].y.toString(2)) + (y[j] || '');
      }
    }

    // Creates the final share strings which contain the share's id and the data allocated to the share
    for (let i = 0; i < totalShares; i++) {
      let shareId = x[i];
      let integerShareId = parseInt(shareId, 16);

      // Sanity check our shareId to make sure its valid
      if (typeof integerShareId !== 'number' || integerShareId % 1 !== 0 || integerShareId < 1 || integerShareId > maxShares) {
        throw new Error(`Share id must be an integer between 1 and ${maxShares}, inclusive.`);
      }

      // Pad our hexadecimal shareId to a minimum of 2 digits as the largest share shareId is 8^2 - 1 which in hex is 'ff'
      shareId = helpers.strings.padLeft(shareId, 2);

      // Reassign x[i] with our new share string
      x[i] = shareId + helpers.strings.binaryToHexadecimal(y[i]);
    }

    return x;
  },


  /**
   * Attempts to combine a given array of shares to derive the original secret
   * @param shares {[String]} Array of share strings which are to be used to derive the original secret
   * @returns {String} Reconstructed secret (if not enough shares are provided this will be garbage data)
   */
  deriveSecret: function(shares) {
    let result = '';
    let x = [];
    let y = [];

    for (let i = 0; i < shares.length; i++) {
      let share = helpers.shareOperations.extractShareComponents(shares[i]);

      // Here we split each share's hexadecimal data into an array of integers. We then copy each item at position `j` for each share into
      // its own array. This ultimately 'rotates' the arrays so that the output changes from something like this:
      //
      //   Share 1 [ 1, 2, 3, 4, 5 ]
      //   Share 2 [ 6, 7, 8, 9, 10]
      //   Share 3 [ 11, 12, 13, 14, 15]
      //
      // Into something like this:
      //
      // [
      //   [ 1, 6, 11 ],
      //   [ 2, 7, 12 ],
      //   [ 3, 8, 13 ],
      //   [ 4, 9, 14 ],
      //   [ 5, 10, 15 ]
      // ]

      // Only process this if we don't already have this share
      if (x.indexOf(share.id) === -1) {
        x.push(share.id);
        let splitShare = helpers.strings.splitNumStringToIntArray(helpers.strings.hexadecimalToBinary(share.data));
        for (let j = 0; j < splitShare.length; j++) {
          y[j] = y[j] || [];
          y[j][x.length - 1] = splitShare[j];
        }
      }

    }

    // We then extract the secret from each array by calculating the lagrange point using each array as a set of coordinates. These
    // secrets are concatenated together to make the binary string version of the original secret.
    for (let i = 0; i < y.length; i++) {
      result = helpers.strings.padLeft(helpers.crypto.lagrange(x, y[i]).toString(2)) + result;
    }

    // Search the string for the first '1' and disregard all 0s before that as these were added via a left-pad. We then convert the
    // remaining binary string back into hexadecimal to get the original secret data
    return helpers.strings.binaryToHexadecimal(result.slice(result.indexOf('1') + 1));
  }
};

module.exports = Shamir;

// For testing
module.exports._helpers = helpers;
