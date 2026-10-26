// Package softaes is a from-scratch, pure-software AES implementation (FIPS PUB
// 197) for 128-, 192- and 256-bit keys. It contains no hardcoded lookup
// tables: the GF(2^8) log/exp tables, the S-box and inverse S-box, the
// inverse MixColumns matrix and the round constants are all derived at
// package init from the two FIPS-197 field parameters (the reduction
// polynomial 0x11b and the affine constant 0x63) plus the MixColumns
// polynomial coefficients {2,3,1,1}.
//
// Cipher implements crypto/cipher's Block interface, so CBC, GCM, CTR and OFB
// work through the standard library, and CFB8 works because Cipher also
// implements BlockCipher. ECB helpers (EncryptECB/DecryptECB) are provided for
// the mode the standard library deliberately omits.
//
// Correctness is verified against three independent sources in the tests:
// Go's crypto/aes, OpenSSL's AES via Python's cryptography package (see
// tools/gen_vectors.py, whose vectors.json this package's tests load), and
// RFC 3602's published AES-CBC test vectors.
//
// Performance is table-driven but straightforward; it is much slower than
// crypto/aes (no AES-NI, no T-tables). Plaintext-dependent S-box lookups are
// not constant-time and may leak through cache-timing side channels; use
// crypto/aes for production secrets.
package softaes
