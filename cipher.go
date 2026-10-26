package softaes

import (
	"crypto/cipher"
	"fmt"
)

// blockSize is the AES block size in bytes (FIPS-197: always 128 bits).
const blockSize = 16

// Compile-time proof that Cipher is usable both as a cipher.Block (CBC, GCM,
// CTR, OFB via crypto/cipher) and as a cipher.BlockCipher (CFB8).
var (
	_ cipher.Block = (*Cipher)(nil)
)

// Cipher is a pure-software AES implementation for 128-, 192- and 256-bit keys.
// All derived tables (S-box, log/exp, inverse MixColumns, round constants) are
// computed once at package init from the FIPS-197 field parameters, so the
// tables do not depend on the key or on any plaintext.
type Cipher struct {
	rounds      int
	keySchedule []byte // (rounds+1)*16 bytes, column-major round keys
}

// NewCipher creates an AES cipher for a 16-, 24- or 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("aes: invalid key size %d, want 16, 24 or 32 bytes", len(key))
	}
	return &Cipher{
		rounds:      roundsForKeySize(len(key) / 4),
		keySchedule: expandKey(key),
	}, nil
}

// BlockSize returns the cipher's block size (16 bytes).
func (c *Cipher) BlockSize() int { return blockSize }

// Size reports the key length accepted by NewCipher for key, or -1 if invalid.
// It implements cipher.BlockCipher, which enables crypto/cipher.NewCFB8*.
func (c *Cipher) Size(key []byte) int {
	switch len(key) {
	case 16, 24, 32:
		return len(key)
	}
	return -1
}

// Block encrypts one block; it satisfies cipher.Block, so crypto/cipher modes
// (CBC, GCM, CTR, ...) work on top of this cipher. dst and src may overlap.
func (c *Cipher) Block(dst, src []byte) { c.Encrypt(dst, src) }

// Encrypt encrypts a 16-byte block from src into dst (dst may alias src).
func (c *Cipher) Encrypt(dst, src []byte) {
	checkBuffers(dst, src)
	state := [16]byte{}
	copy(state[:], src[:blockSize])
	encryptBlock(&state, c.keySchedule, c.rounds)
	copy(dst[:blockSize], state[:])
}

// Decrypt decrypts a 16-byte block from src into dst (dst may alias src).
func (c *Cipher) Decrypt(dst, src []byte) {
	checkBuffers(dst, src)
	state := [16]byte{}
	copy(state[:], src[:blockSize])
	decryptBlock(&state, c.keySchedule, c.rounds)
	copy(dst[:blockSize], state[:])
}

func checkBuffers(dst, src []byte) {
	if len(src) < blockSize || len(dst) < blockSize {
		panic("aes: buffer shorter than the 16-byte AES block")
	}
}

// encryptBlock implements FIPS-197 §5.1 (encryption key schedule + cipher).
func encryptBlock(state *[16]byte, schedule []byte, nr int) {
	addRoundKey(state, schedule[0:16])
	for round := 1; round < nr; round++ {
		subBytes(state)
		shiftRows(state)
		applyMatrix(state, &mixMatrix)
		addRoundKey(state, schedule[round*16:(round+1)*16])
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, schedule[nr*16:(nr+1)*16])
}

// decryptBlock implements the inverse cipher, FIPS-197 §5.2.
func decryptBlock(state *[16]byte, schedule []byte, nr int) {
	addRoundKey(state, schedule[nr*16:(nr+1)*16])
	for round := nr - 1; round >= 1; round-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, schedule[round*16:(round+1)*16])
		applyMatrix(state, &invMixMatrix)
	}
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, schedule[0:16])
}

// The state is FIPS-197's 4x4 column-major array: byte (r, c) lives at r+4c.

func subBytes(state *[16]byte) {
	for i := range state {
		state[i] = subByte(state[i])
	}
}

func invSubBytes(state *[16]byte) {
	for i := range state {
		state[i] = invSubByte(state[i])
	}
}

// shiftRows rotates row r left by r positions (cyclically).
func shiftRows(state *[16]byte) {
	for r := 1; r < 4; r++ {
		var row [4]byte
		for c := 0; c < 4; c++ {
			row[c] = state[r+4*c]
		}
		for c := 0; c < 4; c++ {
			state[r+4*c] = row[(c+r)&3]
		}
	}
}

func invShiftRows(state *[16]byte) {
	for r := 1; r < 4; r++ {
		var row [4]byte
		for c := 0; c < 4; c++ {
			row[c] = state[r+4*c]
		}
		for c := 0; c < 4; c++ {
			state[r+4*c] = row[(c-r+4)&3]
		}
	}
}

func addRoundKey(state *[16]byte, roundKey []byte) {
	for i := range state {
		state[i] ^= roundKey[i]
	}
}

// EncryptECB encrypts src (a multiple of 16 bytes) into dst, block by block.
func (c *Cipher) EncryptECB(dst, src []byte) error {
	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes: ECB needs a multiple of 16 bytes, got %d", len(src))
	}
	if len(dst) < len(src) {
		return fmt.Errorf("aes: dst buffer too small (%d < %d)", len(dst), len(src))
	}
	for i := 0; i < len(src); i += blockSize {
		c.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return nil
}

// DecryptECB decrypts src (a multiple of 16 bytes) into dst, block by block.
func (c *Cipher) DecryptECB(dst, src []byte) error {
	if len(src)%blockSize != 0 {
		return fmt.Errorf("aes: ECB needs a multiple of 16 bytes, got %d", len(src))
	}
	if len(dst) < len(src) {
		return fmt.Errorf("aes: dst buffer too small (%d < %d)", len(dst), len(src))
	}
	for i := 0; i < len(src); i += blockSize {
		c.Decrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return nil
}

// EncryptBlock is a one-shot convenience for a single 16-byte block.
func EncryptBlock(key, plaintext []byte) ([]byte, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != blockSize {
		return nil, fmt.Errorf("aes: plaintext must be exactly %d bytes, got %d", blockSize, len(plaintext))
	}
	dst := make([]byte, blockSize)
	c.Encrypt(dst, plaintext)
	return dst, nil
}

// DecryptBlock is a one-shot convenience for a single 16-byte block.
func DecryptBlock(key, ciphertext []byte) ([]byte, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != blockSize {
		return nil, fmt.Errorf("aes: ciphertext must be exactly %d bytes, got %d", blockSize, len(ciphertext))
	}
	dst := make([]byte, blockSize)
	c.Decrypt(dst, ciphertext)
	return dst, nil
}
