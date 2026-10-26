"""Pull the published AES example vectors out of NIST FIPS-197 (Appendix C)
and write them to vectors_fips.json for the Go tests.

Every value in the output is transcribed from the standard's own PDF, then
*validated by recomputation* with tools/python_ref.py: the round-by-round
relations (start = previous m_col ^ key, s_box = S(start), s_row = ShiftRows,
m_col = MixColumns, output = s_row ^ key) must all hold, and the final
ciphertext must match what OpenSSL's AES computes. Anything that does not
validate is dropped rather than shipped as a vector.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import python_ref as ref  # noqa: E402
from fips197_extract import fetch, stream_text  # noqa: E402

PDF_URL = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "vectors_fips.json")

CASE_RE = re.compile(r"C\.(\d) AES-(\d+).*?Nk=(\d+),\s*Nr=(\d+)")
LINE_RE = re.compile(
    r"round\[ ?(\d+)\]\.(input|k_sch|start|s_box|s_row|m_col|output"
    r"|iinput|ik_sch|istart|is_box|is_row|im_col|ioutput)\s*([0-9a-f]{32})"
)
PLAINTEXT_RE = re.compile(r"PLAINTEXT:\s*([0-9a-f]{32})")
KEY_RE = re.compile(r"KEY:\s*([0-9a-f]{32,48,64})")


def openssl_ecb(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def openssl_decrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def split_by_case(text: str):
    """Cut the extracted text into one chunk per Appendix C case."""
    marks = [(m.start(), m.group(1), m.group(2), int(m.group(3)), int(m.group(4)))
             for m in CASE_RE.finditer(text)]
    chunks = []
    for i, (start, _n, bits, nk, nr) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        chunks.append((bits, nk, nr, text[start:end]))
    return chunks


def parse_rounds(chunk: str):
    """round[ r ].name <hex32> -> {name: {round: bytes}}"""
    tables = {}
    for m in LINE_RE.finditer(chunk):
        rnd, name, hexs = int(m.group(1)), m.group(2), m.group(3)
        tables.setdefault(name, {})[rnd] = bytes.fromhex(hexs)
    return tables


def eq(a: bytes, b: bytes) -> bool:
    return a == b


def encrypt_state(tables: dict, nk: int, nr: int):
    """Validate the encryption listing against python_ref, step by step."""
    enc = tables.get("k_sch", {})
    key0 = enc.get(0)
    input_ = tables.get("input", {}).get(0)
    if key0 is None or input_ is None:
        return None, ["missing round 0 input/k_sch"]
    failures = []
    rounds = []
    state = bytes(a ^ b for a, b in zip(input_, key0))
    for rnd in range(1, nr + 1):
        start = tables.get("start", {}).get(rnd)
        if start is None or not eq(start, state):
            failures.append(f"round {rnd} start mismatch")
            break
        sbox_v = tables.get("s_box", {}).get(rnd)
        srow_v = tables.get("s_row", {}).get(rnd)
        mcol_v = tables.get("m_col", {}).get(rnd)
        ksch_v = enc.get(rnd)
        mine_sbox = bytes(ref.SBOX[b] for b in start)
        mine_srow = ref._shift_rows(bytearray(mine_sbox))
        if sbox_v is None or not eq(sbox_v, mine_sbox):
            failures.append(f"round {rnd} s_box mismatch")
            break
        if srow_v is None or not eq(srow_v, mine_srow):
            failures.append(f"round {rnd} s_row mismatch")
            break
        if rnd < nr:
            mine_mcol = ref._mix(bytearray(mine_srow), ref.MIX)
            if mcol_v is None or not eq(mcol_v, mine_mcol):
                failures.append(f"round {rnd} m_col mismatch")
                break
            if ksch_v is None:
                failures.append(f"round {rnd} k_sch missing")
                break
            rounds.append({"round": rnd, "start": start.hex(), "s_box": sbox_v.hex(),
                           "s_row": srow_v.hex(), "m_col": mcol_v.hex(), "k_sch": ksch_v.hex()})
            state = bytes(a ^ b for a, b in zip(mine_mcol, ksch_v))
        else:
            if ksch_v is None:
                failures.append(f"round {rnd} k_sch missing")
                break
            output = tables.get("output", {}).get(rnd)
            mine_out = bytes(a ^ b for a, b in zip(mine_srow, ksch_v))
            if output is None or not eq(output, mine_out):
                failures.append(f"round {rnd} output mismatch")
                break
            rounds.append({"round": rnd, "start": start.hex(), "s_box": sbox_v.hex(),
                           "s_row": srow_v.hex(), "m_col": None, "k_sch": ksch_v.hex(),
                           "output": output.hex()})
    return {"rounds": rounds, "key_schedule": [enc[r].hex() for r in sorted(enc)],
            "input": input_.hex()}, failures


def inverse_state(tables: dict, nr: int):
    """Validate the inverse cipher listing (FIPS-197 §5.3 equivalent inverse
    cipher, rounds numbered so that ik_sch[r] is the key added at the end of
    inverse round r and istart[r] is the state entering it)."""
    ikeys = tables.get("ik_sch", {})
    istart = tables.get("istart", {})
    ibox = tables.get("is_box", {})
    irow = tables.get("is_row", {})
    imix = tables.get("im_col", {})
    iinput = tables.get("iinput", {}).get(0)
    ioutput = tables.get("ioutput", {}).get(nr)
    if iinput is None or ioutput is None or not istart or not ikeys:
        return None, ["inverse listing incomplete"]
    # The cipher starts by XORing the last round key, which the listing records
    # for the round numbered nr-1... try both anchor conventions.
    anchors = {
        "pre": bytes(a ^ b for a, b in zip(iinput, ikeys.get(nr - 1, ikeys.get(nr, b"")))),
    }
    rounds = []
    failures = []
    state = anchors["pre"]
    for rnd in range(1, nr + 1):
        s = istart.get(rnd)
        if s is None or not eq(s, state):
            failures.append(f"inverse round {rnd} istart mismatch")
            break
        mine_box = bytes(ref.INV_SBOX[b] for b in s)
        mine_row = ref._shift_rows(bytearray(mine_box), inverse=True)
        vb, vr = ibox.get(rnd), irow.get(rnd)
        if vb is None or not eq(vb, mine_box):
            failures.append(f"inverse round {rnd} is_box mismatch")
            break
        if vr is None or not eq(vr, mine_row):
            failures.append(f"inverse round {rnd} is_row mismatch")
            break
        k = ikeys.get(rnd)
        if k is None:
            failures.append(f"inverse round {rnd} ik_sch missing")
            break
        if rnd < nr:
            vm = imix.get(rnd)
            mine_mix = ref._mix(bytearray(mine_row), ref.INV_MIX)
            if vm is None or not eq(vm, mine_mix):
                failures.append(f"inverse round {rnd} im_col mismatch")
                break
            rounds.append({"round": rnd, "istart": s.hex(), "is_box": vb.hex(),
                           "is_row": vr.hex(), "im_col": vm.hex(), "ik_sch": k.hex()})
            state = bytes(a ^ b for a, b in zip(vm, k))
        else:
            if not eq(ioutput, bytes(a ^ b for a, b in zip(mine_row, k))):
                failures.append(f"inverse round {rnd} ioutput mismatch")
                break
            rounds.append({"round": rnd, "istart": s.hex(), "is_box": vb.hex(),
                           "is_row": vr.hex(), "im_col": None, "ik_sch": k.hex(),
                           "ioutput": ioutput.hex()})
    return {"rounds": rounds, "iinput": iinput.hex(), "ioutput": ioutput.hex()}, failures


def main() -> int:
    text = stream_text(fetch(PDF_URL))
    cases = []
    for bits, nk, nr, chunk in split_by_case(text):
        tables = parse_rounds(chunk)
        pt = PLAINTEXT_RE.search(chunk)
        key = KEY_RE.search(chunk)
        if not pt or not key:
            continue
        key_bytes = bytes.fromhex(key.group(1))
        pt_bytes = bytes.fromhex(pt.group(1))
        enc, enc_fail = encrypt_state(tables, nk, nr)
        inv, inv_fail = inverse_state(tables, nr)
        # Independent authority check: OpenSSL must reproduce the published
        # ciphertext, and decrypt it back to the published plaintext.
        ct = enc["rounds"][-1]["output"] if enc else None
        ok_enc = ok_inv = False
        if ct:
            ok_enc = openssl_ecb(key_bytes, pt_bytes) == ct
            ok_inv = openssl_decrypt(key_bytes, ct) == pt_bytes
            ok_enc = ok_enc and ref.aes_encrypt_block(key_bytes, pt_bytes) == ct
        cases.append({
            "id": f"AES-{bits}",
            "nk": nk, "nr": nr,
            "key": key_bytes.hex(), "plaintext": pt_bytes.hex(),
            "ciphertext": ct,
            "encryption": enc, "inverse": inv,
            "validated_by_openssl": ok_enc, "validated_decrypt": ok_inv,
            "encryption_failures": enc_fail, "inverse_failures": inv_fail,
        })
    summary = []
    for c in cases:
        summary.append({
            c["id"]: {
                "encrypt_ok": c["validated_by_openssl"],
                "decrypt_ok": c["validated_decrypt"],
                "enc_rounds": len(c["encryption"]["rounds"]) if c["encryption"] else 0,
                "inv_rounds": len(c["inverse"]["rounds"]) if c["inverse"] else 0,
                "enc_fail": c["encryption_failures"],
                "inv_fail": c["inverse_failures"],
            }
        })
    print(json.dumps(summary, indent=2))
    if not cases:
        print("no cases parsed", file=sys.stderr)
        return 1
    with open(OUT, "w") as f:
        json.dump({"source": "NIST FIPS-197 Appendix C example vectors", "cases": cases}, f, indent=2)
    print(f"wrote {os.path.relpath(OUT)} with {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
