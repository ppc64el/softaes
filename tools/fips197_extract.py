"""Fetch NIST FIPS-197 (the AES standard) and pull the published example
vectors out of the PDF, so the Go/Python code can be checked against numbers
computed by the standard's own reference implementations rather than by us.

No cipher math lives in this script: it only downloads the PDF, inflates the
FlateDecode content streams with zlib, and greps the extracted text.
"""

import re
import sys
import urllib.request
import zlib

PDF_URL = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "aes-verify/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL
        return resp.read()


def stream_text(pdf: bytes) -> str:
    """Inflate every FlateDecode stream in the PDF and keep printable text."""
    chunks = []
    for m in re.finditer(rb"stream\r?\n?(.*?)endstream", pdf, re.S):
        raw = m.group(1)
        try:
            data = zlib.decompress(raw)
        except zlib.error:
            continue
        # PDF text shows up as (string) or [ (str) (str) ] in Tj/TJ operators.
        parts = re.findall(rb"\((?:[^()\\]|\\.)*\)", data)
        line = b"".join(p[1:-1] for p in parts)
        if line.strip():
            chunks.append(line.decode("latin-1", "replace"))
    return "\n".join(chunks)


def main() -> int:
    pdf = fetch(PDF_URL)
    text = stream_text(pdf)
    print(f"pdf bytes: {len(pdf)}, extracted text lines: {len(text.splitlines())}")
    # The example vectors live in Appendix B (encryption) and Appendix C.
    for pat in sys.argv[1:] or ["Example", "Cipher", "Plain", "Key", "Round"]:
        print(f"--- pattern {pat!r} ---")
        hits = [ln.strip() for ln in text.splitlines() if pat.lower() in ln.lower()]
        for ln in hits[:60]:
            print(ln)
        if not hits:
            print("(no matches)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
