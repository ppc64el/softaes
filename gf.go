package softaes

// GF(2^8) arithmetic for AES, computed at init — nothing is hardcoded.
//
// The only spec parameters kept as single constants are the ones FIPS-197
// defines: the field-reduction polynomial below (m(x) = x^8 + x^4 + x^3 + x + 1)
// and, in sbox.go, the affine translation constant. Every table (log/exp,
// S-box, inverse S-box, inverse MixColumns matrix, round constants) is derived
// by this package at startup from those parameters.

// fieldPoly is m(x) as a 9-bit value: bits 8,4,3,1 set → 0x11b.
const fieldPoly = 0x11b

// xtime multiplies by x (the polynomial generator) and reduces modulo m(x).
func xtime(b byte) byte {
	v := uint16(b) << 1
	if v&0x100 != 0 {
		v ^= fieldPoly
	}
	return byte(v)
}

// mulNoTable is a plain "peasant" multiplication in GF(2^8), used only while
// building the lookup tables so that table construction itself needs no
// precomputed numbers.
func mulNoTable(a, b byte) byte {
	var r byte
	for a != 0 {
		if a&1 != 0 {
			r ^= b
		}
		a >>= 1
		b = xtime(b)
	}
	return r
}

// fieldGenerator is a primitive element of GF(2^8)*, discovered by exhaustive
// search at init (FIPS-197 cites 0x03, but the code verifies one itself).
var fieldGenerator byte

// gfExp/gfLog are multiplication/discrete-log tables: exp[i] = g^i, log[g^i] = i.
// exp is duplicated for indices 255..509 so gfMul never needs a modulo.
var (
	gfExp [512]byte
	gfLog [256]byte
)

// isPrimitive reports whether g generates the whole multiplicative group,
// i.e. its multiplicative order is exactly 255 (the group's size).
func isPrimitive(g byte) bool {
	p := byte(1)
	for i := 1; i <= 255; i++ {
		p = mulNoTable(p, g)
		if p == 1 {
			return i == 255
		}
	}
	return false
}

func buildFieldTables() {
	g := byte(0)
	for cand := 2; cand < 256; cand++ {
		if isPrimitive(byte(cand)) {
			g = byte(cand)
			break
		}
	}
	if g == 0 {
		panic("aes: no primitive element found for the AES field polynomial")
	}
	fieldGenerator = g

	p := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = p
		gfLog[p] = byte(i)
		p = mulNoTable(p, g)
	}
	for i := 255; i < len(gfExp); i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul is the table-driven field product. log[0] is never consulted.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv returns the multiplicative inverse; 0 maps to 0, matching the FIPS-197
// convention that the S-box affine stage is applied to 0x00.
func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}
