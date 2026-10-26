package softaes

// AES key schedule (FIPS-197 §5.2/§7.2). Round constants are not hardcoded:
// RCON[i] is xtime applied (i-1) times to 1, i.e. powers of the field
// generator x, so the sequence 01,02,04,08,10,20,40,80,1b,36,... emerges from
// the field arithmetic itself.

func roundsForKeySize(nk int) int {
	switch nk {
	case 4:
		return 10 // AES-128
	case 6:
		return 12 // AES-192
	case 8:
		return 14 // AES-256
	}
	return 0
}

func rotWord(w [4]byte) [4]byte {
	return [4]byte{w[1], w[2], w[3], w[0]}
}

func subWord(w [4]byte) [4]byte {
	return [4]byte{subByte(w[0]), subByte(w[1]), subByte(w[2]), subByte(w[3])}
}

// expandKey returns the round-key schedule as (nr+1)*16 bytes, laid out
// column-major so round key r is schedule[r*16 : (r+1)*16].
func expandKey(key []byte) []byte {
	nk := len(key) / 4
	nb := 4
	nr := roundsForKeySize(nk)
	total := nb * (nr + 1)

	w := make([]byte, total*4)
	copy(w, key)

	rcon := byte(1)
	for i := nk; i < total; i++ {
		var temp [4]byte
		copy(temp[:], w[(i-1)*4:i*4])

		switch {
		case i%nk == 0:
			temp = subWord(rotWord(temp))
			temp[0] ^= rcon
			rcon = xtime(rcon)
		case nk == 8 && i%nk == 4:
			temp = subWord(temp)
		}

		for j := 0; j < 4; j++ {
			w[i*4+j] = w[(i-nk)*4+j] ^ temp[j]
		}
	}
	return w
}
