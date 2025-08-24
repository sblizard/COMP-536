# crib_drag.py
from typing import List, Optional

TARGET_IDX = 8         # second-to-last ciphertext in your data (0-based)
SPACE_THRESHOLD = 5    # how many letter-hits needed at a position to assume target has a space
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E

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

def bxor_min(a: bytes, b: bytes) -> bytes:
    """XOR up to the length of the shorter input (the useful overlap)."""
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))

def is_letter(b: int) -> bool:
    """True if b is ASCII letter A–Z or a–z."""
    return (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)

def is_printable(b: int) -> bool:
    return PRINTABLE_MIN <= b <= PRINTABLE_MAX

def show_lengths(cts: List[bytes]) -> None:
    print("Ciphertext lengths:")
    for i, ct in enumerate(cts):
        print(f"  CT {i}: {len(ct)} bytes")
    print()

def infer_spaces_and_key_prefix(cts: List[bytes], tgt: int, threshold: int):
    """
    For target index `tgt`, compute (CT_tgt ^ CT_j) over the overlap for all j,
    count 'letter' hits per position, and mark target positions likely to be SPACE.
    Return:
      - space_mask: List[bool] of length L (L = len(ct[tgt])) where True => likely space
      - key_prefix: bytearray of length L with derived key bytes where known, else None (as -1)
    """
    L = len(cts[tgt])
    counts = [0] * L
    # collect pairwise XORs for display/debug if you want
    xors = []

    for j, ctj in enumerate(cts):
        x = bxor_min(cts[tgt], ctj)
        xors.append(x)
        for k, b in enumerate(x):
            if is_letter(b):
                counts[k] += 1

    # Decide space positions for target based on threshold
    space_mask = [c >= threshold for c in counts]

    # Build key prefix: if P_tgt[k] is a space (0x20), then K[k] = C_tgt[k] ^ 0x20
    key_prefix = bytearray(L)
    known = [False] * L
    for k in range(L):
        if space_mask[k]:
            key_prefix[k] = cts[tgt][k] ^ 0x20
            known[k] = True

    return space_mask, key_prefix, known, counts, xors

def apply_crib(cts: List[bytes], key_prefix: bytearray, known: List[bool],
               ct_index: int, crib: str, offset: int = 0) -> None:
    """
    Apply a guessed plaintext crib to ciphertext `ct_index` at `offset` (within target prefix length).
    This updates the key_prefix and known-mask where the crib fits.
    """
    L = min(len(key_prefix), len(cts[ct_index]) - offset, len(crib))
    if L <= 0:
        return
    crib_bytes = crib.encode("utf-8")[:L]
    for i in range(L):
        k = offset + i
        key_prefix[k] = cts[ct_index][k] ^ crib_bytes[i]
        known[k] = True

def reveal_with_key(cts: List[bytes], key_prefix: bytearray, known: List[bool]) -> List[str]:
    """
    Reveal printable characters for ALL ciphertexts where the key is known (within prefix length),
    using '.' for unknown/non-printable.
    """
    L = len(key_prefix)
    out = []
    for idx, ct in enumerate(cts):
        n = min(L, len(ct))
        row = []
        for k in range(n):
            if known[k]:
                ch = ct[k] ^ key_prefix[k]
                row.append(chr(ch) if is_printable(ch) else '?')
            else:
                row.append('.')
        out.append(f"PT_guess[{idx}]: {''.join(row)}")
    return out

def print_space_map(space_mask: List[bool], counts: List[int]) -> None:
    """
    Visualize which positions in the target are likely spaces and how many 'letter hits' each got.
    """
    L = len(space_mask)
    line_mask = ''.join(' ' if space_mask[k] else '.' for k in range(L))
    line_hits = ' '.join(f"{counts[k]:2d}" for k in range(L))
    print("Likely spaces in target (spaces shown as ' '):")
    print(line_mask)
    print("Letter-hit counts per position:")
    print(line_hits)
    print()

def reprint_reveals(cts, key_prefix, known):
    print("\nReveals with current key:")
    for idx, line in enumerate(reveal_with_key(cts, key_prefix, known)):
        print(line)

def recover_target_plaintext(cts, key_prefix, known, tgt_idx):
    L = min(len(key_prefix), len(cts[tgt_idx]))
    out = []
    for k in range(L):
        if known[k]:
            ch = cts[tgt_idx][k] ^ key_prefix[k]
            out.append(chr(ch) if PRINTABLE_MIN <= ch <= PRINTABLE_MAX else '?')
        else:
            out.append('.')
    print(f"\nPT_guess for CT {tgt_idx} (first {L} bytes): {''.join(out)}")


def main():
    cts = load_ciphertexts()
    show_lengths(cts)

    tgt = TARGET_IDX
    if tgt < 0 or tgt >= len(cts):
        raise IndexError(f"TARGET_IDX={tgt} is out of range (we have {len(cts)} ciphertexts).")

    # Infer spaces & key prefix from target
    space_mask, key_prefix, known, counts, xors = infer_spaces_and_key_prefix(
        cts, tgt, SPACE_THRESHOLD
    )

    print(f"Using CT {tgt} as target (length {len(cts[tgt])}):")
    print_space_map(space_mask, counts)

    # Initial reveals based on target-space heuristic
    print("Initial reveals (derived from target's likely spaces):")
    for line in reveal_with_key(cts, key_prefix, known):
        print(line)

    # --- Apply cribs to grow the known key ---
    # 1) Your earlier run showed CT 1 starts with "The "
    apply_crib(cts, key_prefix, known, ct_index=1, crib="The ", offset=0)

    # 2) CT 6 looked like "Call" -> try the classic opener
    apply_crib(cts, key_prefix, known, ct_index=6, crib="Call me Ishmael", offset=0)

    # 3) Add more guesses as you recognize words; examples (comment/uncomment as needed):
    # apply_crib(cts, key_prefix, known, ct_index=0, crib="From ", offset=0)
    # apply_crib(cts, key_prefix, known, ct_index=2, crib="It was ", offset=0)
    # apply_crib(cts, key_prefix, known, ct_index=3, crib="Once ", offset=0)

    # Reprint reveals and show the short target plaintext (CT 8)
    reprint_reveals(cts, key_prefix, known)
    recover_target_plaintext(cts, key_prefix, known, tgt_idx=TARGET_IDX)

if __name__ == "__main__":
    main()
