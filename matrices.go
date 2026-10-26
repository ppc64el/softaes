package softaes

// MixColumns matrices. The forward matrix is built from the circulant
// coefficients of the Rijndael polynomial a(x) = {03,01,02,03} (FIPS-197 §4.2),
// i.e. the circulant rows of (2,3,1,1); the inverse matrix is obtained by
// Gauss-Jordan elimination over GF(2^8) at init — InvMixColumns coefficients
// such as 0xb5/0x9f/0xd5/0x88 are never hardcoded.

var (
	mixMatrix    [4][4]byte
	invMixMatrix [4][4]byte
)

func buildMixMatrix() [4][4]byte {
	base := [4]byte{2, 3, 1, 1}
	var m [4][4]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			m[r][c] = base[(c-r)&3]
		}
	}
	return m
}

// invertMatrix Gauss-Jordans a 4x4 matrix over GF(2^8), augmenting with the
// identity. Returns ok=false if the matrix is singular.
func invertMatrix(m [4][4]byte) ([4][4]byte, bool) {
	var work [4][8]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			work[r][c] = m[r][c]
		}
		work[r][4+r] = 1
	}

	for col := 0; col < 4; col++ {
		pivot := -1
		for r := 0; r < 4; r++ {
			if work[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot == -1 {
			return [4][4]byte{}, false
		}
		if pivot != col {
			for c := 0; c < 8; c++ {
				work[pivot][c], work[col][c] = work[col][c], work[pivot][c]
			}
		}
		pivotInv := gfInv(work[col][col])
		for c := 0; c < 8; c++ {
			work[col][c] = gfMul(work[col][c], pivotInv)
		}
		for r := 0; r < 4; r++ {
			if r == col || work[r][col] == 0 {
				continue
			}
			f := work[r][col]
			for c := 0; c < 8; c++ {
				work[r][c] ^= gfMul(f, work[col][c])
			}
		}
	}

	var out [4][4]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			out[r][c] = work[r][4+c]
		}
	}
	return out, true
}

// applyMatrix multiplies each state column (a column-major 4-byte vector) by m.
func applyMatrix(state *[16]byte, m *[4][4]byte) {
	for c := 0; c < 4; c++ {
		var a [4]byte
		for r := 0; r < 4; r++ {
			a[r] = state[4*c+r]
		}
		for r := 0; r < 4; r++ {
			var acc byte
			for j := 0; j < 4; j++ {
				acc ^= gfMul(m[r][j], a[j])
			}
			state[4*c+r] = acc
		}
	}
}

func init() {
	buildFieldTables()
	buildSBox()

	mixMatrix = buildMixMatrix()
	var ok bool
	invMixMatrix, ok = invertMatrix(mixMatrix)
	if !ok {
		panic("aes: MixColumns matrix is not invertible over GF(2^8)")
	}
}
