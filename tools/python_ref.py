"""Independent pure-Python AES reference implementation (FIPS-197).

Deliberately derived through *different* code paths than the Go package so it
can cross-check the Go numbers:
  * multiplicative inverse via exponentiation a^254 (square-and-multiply),
    not via log tables
  * affine transform via the explicit bit matrix of FIPS-197 sec.4.2,
    not via byte rotations
  * inverse MixColumns matrix via Gauss-Jordan elimination in Python

No lookup tables of numbers are hardcoded: the primitive element is searched
for at runtime, and every table is computed from the field polynomial.
"""

FIELD_POLY = 0x11b  # m(x) = x^8 + x^4 + x^3 + x + 1 (FIPS-197 sec.4.2)
AFFINE_C = 0x63     # affine translation vector c (FIPS-197 sec.4.2)


def xtime(b):
    v = b << 1
    if v & 0x100:
        v ^= FIELD_POLY
    return v & 0xFF


def gf_mul(a, b):
    """Peasant multiplication in GF(2^8)."""
    r = 0
    while a:
        if a & 1:
            r ^= b
        a >>= 1
        b = xtime(b)
    return r


def is_primitive(g):
    p = 1
    for i in range(1, 256):
        p = gf_mul(p, g)
        if p == 1:
            return i == 255
    return False


def find_generator():
    for g in range(2, 256):
        if is_primitive(g):
            return g
    raise AssertionError("no primitive element found")


GENERATOR = find_generator()


def gf_pow(a, e):
    """Exponentiation by squaring in GF(2^8)."""
    r, base = 1, a
    while e:
        if e & 1:
            r = gf_mul(r, base)
        base = gf_mul(base, base)
        e >>= 1
    return r


def gf_inverse(a):
    """a^-1 = a^254 (no log tables); inverse of 0 defined as 0 by convention."""
    return gf_pow(a, 254) if a else 0


def affine(b):
    """FIPS-197 affine matrix applied bit-by-bit (LSB is bit 0)."""
    out = 0
    for i in range(8):
        v = (b >> i) & 1
        for k in range(1, 5):
            v ^= (b >> ((i + k) & 7)) & 1
        v ^= (AFFINE_C >> i) & 1
        out |= v << i
    return out


SBOX = [affine(gf_inverse(x)) for x in range(256)]
INV_SBOX = [0] * 256
for x, y in enumerate(SBOX):
    INV_SBOX[y] = x


def build_mix_matrix():
    base = [2, 3, 1, 1]  # circulant coefficients of a(x) = {03,01,02,03}
    return [[base[(c - r) % 4] for c in range(4)] for r in range(4)]


def matrix_inverse(m):
    """Gauss-Jordan over GF(2^8)."""
    work = [[0] * 8 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            work[r][c] = m[r][c]
        work[r][4 + r] = 1
    for col in range(4):
        pivot = None
        for r in range(4):
            if work[r][col]:
                pivot = r
                break
        if pivot is None:
            raise AssertionError("singular matrix")
        if pivot != col:
            work[pivot], work[col] = work[col], work[pivot]
        pinv = gf_inverse(work[col][col])
        work[col] = [gf_mul(v, pinv) for v in work[col]]
        for r in range(4):
            if r == col or work[r][col] == 0:
                continue
            f = work[r][col]
            work[r] = [work[r][c] ^ gf_mul(f, work[col][c]) for c in range(8)]
    return [[work[r][4 + c] for c in range(4)] for r in range(4)]


MIX = build_mix_matrix()
INV_MIX = matrix_inverse(MIX)


def expand_key(key):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    total = 4 * (nr + 1)
    w = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, total):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= rcon                           # + RCON (computed by xtime)
            rcon = xtime(rcon)
        elif nk == 8 and i % nk == 4:
            t = [SBOX[b] for b in t]               # SubWord (AES-256 extra step)
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return nr, w


def _add_round_key(state, w, rnd):
    """XOR round key `rnd` into the column-major state.

    FIPS-197 sec.3.3: state byte i (i = r + 4c, column-major) belongs to
    word c, byte position r within that word; round key words are the flat
    words w[4*rnd .. 4*rnd+3].
    """
    for i in range(16):
        state[i] ^= w[rnd * 4 + i // 4][i % 4]


def _sub_bytes(state, table):
    for i in range(16):
        state[i] = table[state[i]]


def _shift_rows(state, inverse=False):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        for c in range(4):
            state[r + 4 * c] = row[(c - r) % 4] if inverse else row[(c + r) % 4]


def _mix(state, m):
    for c in range(4):
        a = [state[4 * c + r] for r in range(4)]
        for r in range(4):
            state[4 * c + r] = gf_mul(m[r][0], a[0]) ^ gf_mul(m[r][1], a[1]) ^ \
                gf_mul(m[r][2], a[2]) ^ gf_mul(m[r][3], a[3])


def aes_encrypt_block(key, block):
    nr, w = expand_key(key)
    state = list(block)
    _add_round_key(state, w, 0)
    for rnd in range(1, nr):
        _sub_bytes(state, SBOX)
        _shift_rows(state)
        _mix(state, MIX)
        _add_round_key(state, w, rnd)
    _sub_bytes(state, SBOX)
    _shift_rows(state)
    _add_round_key(state, w, nr)
    return bytes(state)


def aes_decrypt_block(key, block):
    nr, w = expand_key(key)
    state = list(block)
    _add_round_key(state, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _shift_rows(state, inverse=True)
        _sub_bytes(state, INV_SBOX)
        _add_round_key(state, w, rnd)
        _mix(state, INV_MIX)
    _shift_rows(state, inverse=True)
    _sub_bytes(state, INV_SBOX)
    _add_round_key(state, w, 0)
    return bytes(state)


def cbc_encrypt(key, iv, data):
    assert len(data) % 16 == 0 and len(iv) == 16
    x = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], x))
        x = aes_encrypt_block(key, block)
        out += x
    return bytes(out)


def sbox_hex():
    return "".join(f"{b:02x}" for b in SBOX)


if __name__ == "__main__":
    print(sbox_hex())
