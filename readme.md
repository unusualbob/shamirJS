Shamir JS
=========

This is an implementation of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing) in javascript designed to run on NodeJS.

## Usage

### generateShares(secret, totalShares, requiredShares, padLength)

Splits the given hexadecimal `secret` into a given `totalShares` wherein at least `requiredShares` shares must later be combined to recover the `secret`.

Example:
```
let secret = 'shamirSecretTest';
let hexSecret = Buffer.from(secret).toString('hex');
let shares = Shamir.generateShares(hexSecret, 5, 3);

console.log(shares);
// [ '01cce9a3904d0b9b334f75be3b4d9083b4a2fededacafca5ce6a202f43dd449003',
//   '025c7fbf732b041ebec19c1c64f1a417f797b41d7d622855a32ccfe9e6c23cb417',
//   '0390961ce3660f858d8ee9a25ecf5cf52e5c3890c2cba69519128ab5d170533c4f',
//   '04fb04d4c3a840e826fee0d18fb5690b9041c8f6a444b78b05b4acd29a5f06e314',
//   '0537ed7753e54b7315b1956fb58b91e9498a447b1bed394bbf8ae98eaded696b4c' ]
```

### deriveSecret(shares)

Combines the given `shares` array to derive the original `secret`. You must provide at least `requiredShares` for this operation to succeed.

Example:
```
let secretDataHex = Shamir.deriveSecret([
  '01cce9a3904d0b9b334f75be3b4d9083b4a2fededacafca5ce6a202f43dd449003',
  '025c7fbf732b041ebec19c1c64f1a417f797b41d7d622855a32ccfe9e6c23cb417',
  '0537ed7753e54b7315b1956fb58b91e9498a447b1bed394bbf8ae98eaded696b4c'
]);

let secret = Buffer.from(secretDataHex, 'hex').toString('utf-8');
console.log(secret);

// shamirSecretTest
```

## How it works

Effectively since the input secret is a string and Shamir requires an integer we cannot directly apply it. Instead, we apply Shamir to each
individual byte of the secret. This also adds a bit of security, as if any individual polynomial is weak in some way then at most one byte
of the secret is derived.To do this, we first require the secret be converted to hexadecimal, which makes it semi numeric. Next we cut the
input secret into individual bytes which is pretty easy with the hex. We then create a randomized polynomial function for each byte, where
f(0) = the byte. Each output share then gets a coordinate corresponding to that polynomial function for each byte in the secret. This means
that ultimately each share will be almost the same length as the original secret, within margin of padding which is up to 16 bytes.

Each polynomial function is calculated within a finite field of size 256, so the maximum participants is 255.

## Security
This code has not been audited in any way. Use this at your own risk.

# Attributions

Lots of inspiration from the following:

* https://github.com/mozilla/sops/tree/master/shamir
* https://github.com/grempe/secrets.js
* https://github.com/djpohly/libgfshare
