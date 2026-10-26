# softaes

A from-scratch, pure-software AES implementation (FIPS PUB 197) for 128-, 192-
and 256-bit keys, in Go.

It contains **no hardcoded lookup tables**: the GF(2^8) log/exp tables, the
S-box and inverse S-box, the inverse MixColumns matrix and the round constants
are all derived at package init from the two FIPS-197 field parameters (the
reduction polynomial `0x11b` and the affine constant `0x63`) plus the
MixColumns polynomial coefficients `{2,3,1,1}`.

```go
import "github.com/ppc64el/softaes"

c, err := softaes.NewCipher(key) // 16, 24 or 32 bytes
if err != nil { ... }
c.Encrypt(dst, src) // cipher.Block
c.Decrypt(dst, src)

c.EncryptECB(dst, src) // whole blocks, error if len(src) isn't a multiple of 16
c.DecryptECB(dst, src)

ct, err := softaes.EncryptBlock(key, plaintext) // one-shot, exactly one block
pt, err := softaes.DecryptBlock(key, ct)
```

`Cipher` implements `crypto/cipher`'s `Block` interface, so CBC, GCM, CTR and
OFB work through the standard library, and CFB8 works because `Cipher` also
implements `cipher.BlockCipher`. ECB helpers (`EncryptECB` / `DecryptECB`) are
provided for the mode the standard library deliberately omits.

## Layout

| Path | Contents |
| --- | --- |
| `gf.go` | GF(2^8) arithmetic: `xtime`, log/exp tables |
| `sbox.go` | S-box / inverse S-box derived from inversion + the affine transform |
| `matrices.go` | MixColumns built from the circulant coefficients; InvMixColumns by Gauss-Jordan elimination over GF(2^8) |
| `keyexpansion.go` | Key schedule; round constants are powers of the field generator `x` |
| `cipher.go` | `Cipher`, block encryption/decryption, ECB helpers |
| `doc.go` | Package documentation |
| `tools/` | Python helpers used to derive reference vectors |

## Tools

```sh
python3 tools/fips197_vectors.py   # writes vectors_fips.json from the FIPS-197 PDF
```

`tools/fips197_extract.py` fetches NIST FIPS-197 and `tools/python_ref.py` is an
independent Python reference implementation. Every vector the extractor emits is
validated by recomputation (the round-by-round relations must hold and the final
ciphertext must match OpenSSL's AES); anything that does not validate is dropped
rather than shipped.

## Limitations

Performance is table-driven but straightforward, and much slower than
`crypto/aes` (no AES-NI, no T-tables). Plaintext-dependent S-box lookups are not
constant-time and may leak through cache-timing side channels; use `crypto/aes`
for production secrets.
