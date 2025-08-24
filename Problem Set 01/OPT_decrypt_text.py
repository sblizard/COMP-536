from typing import List

def load_ciphertexts() -> List[bytes]:
    """
    Reads texts.txt where ciphertext blocks are separated by blank lines.
    If a block has multiple non-blank lines, we keep ONLY the last line (assumed ciphertext hex).
    Returns: list[bytes]
    """
    cts_hex = []
    block = []
    with open("texts.txt", "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                if block:
                    cts_hex.append(block[-1])
                    block = []
                continue
            block.append(line)
        if block:
            cts_hex.append(block[-1])

    cts = []
    for i, h in enumerate(cts_hex):
        try:
            cts.append(bytes.fromhex(h))
        except ValueError as e:
            raise ValueError(f"Block {i} is not valid hex:\n{h}") from e
    return cts

def bxor(a: bytes, b: bytes) -> bytes:
    """XOR up to the length of the longer input, padding the shorter with zeros."""
    n = max(len(a), len(b))
    out = bytearray(n)
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out[i] = x ^ y
    return bytes(out)

def main():
    cts = load_ciphertexts()

    # sanity check
    for i, ct in enumerate(cts):
        if any(bxor(ct, ct)):
            raise RuntimeError(f"Sanity check failed at index {i}")

    for i, cti in enumerate(cts):
        for j, ctj in enumerate(cts):
            x = bxor(cti, ctj)
            print(f"Text {i} XOR Text {j} =")
            print(x.hex(), end="\n\n")

if __name__ == "__main__":
    main()
