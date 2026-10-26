package softaes

// The AES S-box, derived at init: S(x) = A(x^-1) + c, where x^-1 is the
// multiplicative inverse in GF(2^8) (with 0^-1 := 0 by convention) and A is
// the FIPS-197 §4.2 affine transform.

// affineXorConst is the translation vector c = {1,1,0,0,0,1,1,1} (LSB-first
// bit vector) from FIPS-197 §4.2 — a single specification constant, not a table.
const affineXorConst = 0x63

// rotl8 rotates a byte left by n bits; callers use n in 1..7.
func rotl8(b byte, n uint) byte {
	return b<<n | b>>(8-n)
}

var (
	sbox    [256]byte
	invSbox [256]byte
)

func buildSBox() {
	// A(b) in compact byte form: b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ c.
	// This is the bit-matrix of FIPS-197 §4.2 written as rotations; the
	// equivalent bit-by-bit matrix form is exercised independently in the tests.
	for x := 0; x < 256; x++ {
		inv := gfInv(byte(x))
		y := inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ affineXorConst
		sbox[x] = y
		invSbox[y] = byte(x)
	}
}

func subByte(b byte) byte    { return sbox[b] }
func invSubByte(b byte) byte { return invSbox[b] }
