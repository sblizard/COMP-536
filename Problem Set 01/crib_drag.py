# crib_drag.py
from typing import List, Optional

TARGET_IDX = 8
SPACE_THRESHOLD = 5
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E

def load_ciphertexts() -> List[bytes]:
    """
    Reads texts.txt where ciphertext blocks are separated by blank lines.
    If a block has multiple non-blank lines, concatenate them all to form the complete ciphertext hex.
    Returns: list[bytes]
    """
    ciphertext_hex_strings = []
    current_block = []
    with open("texts.txt", "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line:
                if current_block:
                    # Concatenate all lines in the block to form complete hex string
                    complete_hex = ''.join(current_block)
                    ciphertext_hex_strings.append(complete_hex)
                    current_block = []
                continue
            current_block.append(line)
        if current_block:
            # Handle the last block if file doesn't end with blank line
            complete_hex = ''.join(current_block)
            ciphertext_hex_strings.append(complete_hex)

    ciphertexts = []
    for block_index, hex_string in enumerate(ciphertext_hex_strings):
        try:
            ciphertexts.append(bytes.fromhex(hex_string))
        except ValueError as e:
            raise ValueError(f"Block {block_index} is not valid hex:\n{hex_string}") from e
    return ciphertexts

def bitwise_xor_minimum_length(first_bytes: bytes, second_bytes: bytes) -> bytes:
    """XOR up to the length of the shorter input (the useful overlap)."""
    minimum_length = min(len(first_bytes), len(second_bytes))
    return bytes(x ^ y for x, y in zip(first_bytes[:minimum_length], second_bytes[:minimum_length]))

def is_ascii_letter(byte_value: int) -> bool:
    """True if byte_value is ASCII letter A–Z or a–z."""
    return (0x41 <= byte_value <= 0x5A) or (0x61 <= byte_value <= 0x7A)

def is_printable_ascii(byte_value: int) -> bool:
    return PRINTABLE_MIN <= byte_value <= PRINTABLE_MAX

def show_ciphertext_lengths(ciphertexts: List[bytes]) -> None:
    print("Ciphertext lengths:")
    for index, ciphertext in enumerate(ciphertexts):
        print(f"  CT {index}: {len(ciphertext)} bytes")
    print()

def infer_spaces_and_derive_key_prefix(ciphertexts: List[bytes], target_index: int, letter_hit_threshold: int):
    """
    For target index `target_index`, compute (CT_target ^ CT_j) over the overlap for all j,
    count 'letter' hits per position, and mark target positions likely to be SPACE.
    Return:
      - space_positions: List[bool] of length L (L = len(ct[target_index])) where True => likely space
      - key_prefix: bytearray of length L with derived key bytes where known, else None (as -1)
    """
    target_length = len(ciphertexts[target_index])
    letter_hit_counts = [0] * target_length

    xor_results = []

    for other_index, other_ciphertext in enumerate(ciphertexts):
        xor_result = bitwise_xor_minimum_length(ciphertexts[target_index], other_ciphertext)
        xor_results.append(xor_result)
        for position, byte_value in enumerate(xor_result):
            if is_ascii_letter(byte_value):
                letter_hit_counts[position] += 1

    # Decide space positions for target based on threshold
    space_positions = [count >= letter_hit_threshold for count in letter_hit_counts]

    # Build key prefix: if P_target[k] is a space (0x20), then K[k] = C_target[k] ^ 0x20
    key_prefix = bytearray(target_length)
    known_key_positions = [False] * target_length
    for position in range(target_length):
        if space_positions[position]:
            key_prefix[position] = ciphertexts[target_index][position] ^ 0x20
            known_key_positions[position] = True

    return space_positions, key_prefix, known_key_positions, letter_hit_counts, xor_results

def apply_known_plaintext_crib(ciphertexts: List[bytes], key_prefix: bytearray, known_key_positions: List[bool],
               ciphertext_index: int, known_plaintext_crib: str, position_offset: int = 0) -> None:
    """
    Apply a guessed plaintext crib to ciphertext `ciphertext_index` at `position_offset` (within target prefix length).
    This updates the key_prefix and known-mask where the crib fits.
    """
    max_crib_length = min(len(key_prefix), len(ciphertexts[ciphertext_index]) - position_offset, len(known_plaintext_crib))
    if max_crib_length <= 0:
        return
    crib_bytes = known_plaintext_crib.encode("utf-8")[:max_crib_length]
    for byte_index in range(max_crib_length):
        key_position = position_offset + byte_index
        key_prefix[key_position] = ciphertexts[ciphertext_index][key_position] ^ crib_bytes[byte_index]
        known_key_positions[key_position] = True

def reveal_plaintexts_with_known_key(ciphertexts: List[bytes], key_prefix: bytearray, known_key_positions: List[bool]) -> List[str]:
    """
    Reveal printable characters for ALL ciphertexts where the key is known (within prefix length),
    using '.' for unknown/non-printable.
    """
    key_length = len(key_prefix)
    revealed_plaintexts = []
    for ciphertext_index, ciphertext in enumerate(ciphertexts):
        decryption_length = min(key_length, len(ciphertext))
        decrypted_characters = []
        for position in range(decryption_length):
            if known_key_positions[position]:
                decrypted_byte = ciphertext[position] ^ key_prefix[position]
                decrypted_characters.append(chr(decrypted_byte) if is_printable_ascii(decrypted_byte) else '?')
            else:
                decrypted_characters.append('.')
        revealed_plaintexts.append(f"PT_guess[{ciphertext_index}]: {''.join(decrypted_characters)}")
    return revealed_plaintexts

def print_space_probability_map(space_positions: List[bool], letter_hit_counts: List[int]) -> None:
    """
    Visualize which positions in the target are likely spaces and how many 'letter hits' each got.
    """
    target_length = len(space_positions)
    space_visualization = ''.join(' ' if space_positions[position] else '.' for position in range(target_length))
    hit_count_line = ' '.join(f"{letter_hit_counts[position]:2d}" for position in range(target_length))
    print("Likely spaces in target (spaces shown as ' '):")
    print(space_visualization)
    print("Letter-hit counts per position:")
    print(hit_count_line)
    print()

def print_current_decryption_results(ciphertexts, key_prefix, known_key_positions):
    print("\nReveals with current key:")
    for ciphertext_index, revealed_line in enumerate(reveal_plaintexts_with_known_key(ciphertexts, key_prefix, known_key_positions)):
        print(revealed_line)

def recover_target_ciphertext_plaintext(ciphertexts, key_prefix, known_key_positions, target_ciphertext_index):
    decryption_length = min(len(key_prefix), len(ciphertexts[target_ciphertext_index]))
    decrypted_characters = []
    for position in range(decryption_length):
        if known_key_positions[position]:
            decrypted_byte = ciphertexts[target_ciphertext_index][position] ^ key_prefix[position]
            decrypted_characters.append(chr(decrypted_byte) if PRINTABLE_MIN <= decrypted_byte <= PRINTABLE_MAX else '?')
        else:
            decrypted_characters.append('.')
    print(f"\nPT_guess for CT {target_ciphertext_index} (first {decryption_length} bytes): {''.join(decrypted_characters)}")


def recover_key(ciphertext: bytes, plaintext: str) -> bytes:
    """Recover the key used for encryption by XORing the ciphertext with the plaintext."""
    plaintext_bytes = plaintext.encode('utf-8')
    return bitwise_xor_minimum_length(ciphertext, plaintext_bytes)

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt the ciphertext using the key by XORing them."""
    # Only decrypt up to the length of the shorter input
    min_length = min(len(ciphertext), len(key))
    result = bytearray()
    for i in range(min_length):
        decrypted_byte = ciphertext[i] ^ key[i]
        result.append(decrypted_byte)
    return bytes(result)

def main():
    ciphertexts = load_ciphertexts()
    show_ciphertext_lengths(ciphertexts)

    target_ciphertext_index = TARGET_IDX
    if target_ciphertext_index < 0 or target_ciphertext_index >= len(ciphertexts):
        raise IndexError(f"TARGET_IDX={target_ciphertext_index} is out of range (we have {len(ciphertexts)} ciphertexts).")

    # Infer spaces & key prefix from target
    space_positions, key_prefix, known_key_positions, letter_hit_counts, xor_results = infer_spaces_and_derive_key_prefix(
        ciphertexts, target_ciphertext_index, SPACE_THRESHOLD
    )

    print(f"Using CT {target_ciphertext_index} as target (length {len(ciphertexts[target_ciphertext_index])}):")
    print_space_probability_map(space_positions, letter_hit_counts)

    # Initial reveals based on target-space heuristic
    print("Initial reveals (derived from target's likely spaces):")
    for revealed_line in reveal_plaintexts_with_known_key(ciphertexts, key_prefix, known_key_positions):
        print(revealed_line)

    # --- Apply cribs to grow the known key ---
    # 1) Your earlier run showed CT 1 starts with "The "
    apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, ciphertext_index=1, known_plaintext_crib="The ", position_offset=0)

    # 2) CT 6 looked like "Call" -> try the classic opener
    apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, ciphertext_index=6, known_plaintext_crib="Call me Ishmael", position_offset=0)

    # 3) Add more guesses as you recognize words; examples (comment/uncomment as needed):
    # apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, ciphertext_index=0, known_plaintext_crib="From ", position_offset=0)
    # apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, ciphertext_index=2, known_plaintext_crib="It was ", position_offset=0)
    # apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, ciphertext_index=3, known_plaintext_crib="Once ", position_offset=0)

    # Let's extend our knowledge step by step based on what we can clearly see
    print("\n=== Applying step-by-step cribs for CT 6 ===")
    
    # First, apply what we can clearly see from CT 6
    ct6_partial = "The thousand injuries of Fortunato I had borne as I best could; but when he ventured upon insult I vowed revenge. You, who so well know the nature of my soul, will not suppose, however, that I gave utterance to a threat. At length I would be avenged; this was a point definitively settled—but the very definitiveness with which it was resolved precluded the idea of risk."
    apply_known_plaintext_crib(ciphertexts, key_prefix, known_key_positions, 
                              ciphertext_index=6, 
                              known_plaintext_crib=ct6_partial, 
                              position_offset=0)
    
    print(f"Applied {len(ct6_partial)} characters from CT 6")
    print(f"Now we have key knowledge for {sum(known_key_positions)} positions")
    
    # Reprint reveals and show the target plaintext (CT 8) using the extended key
    print_current_decryption_results(ciphertexts, key_prefix, known_key_positions)
    recover_target_ciphertext_plaintext(ciphertexts, key_prefix, known_key_positions, target_ciphertext_index=TARGET_IDX)
    
    # Now decrypt CT 8 using the key we've built up from the cribs
    print(f"\n=== Decrypting CT {TARGET_IDX} with recovered key ===")
    decryption_length = min(len(key_prefix), len(ciphertexts[TARGET_IDX]))
    decrypted_bytes = bytearray()
    
    for position in range(decryption_length):
        if known_key_positions[position]:
            decrypted_byte = ciphertexts[TARGET_IDX][position] ^ key_prefix[position]
            decrypted_bytes.append(decrypted_byte)
        else:
            # We don't know this key position, so we can't decrypt this byte
            break
    
    print(f"Successfully decrypted {len(decrypted_bytes)} bytes of CT {TARGET_IDX}")
    
    # Try to decode as UTF-8
    try:
        decoded_text = bytes(decrypted_bytes).decode('utf-8', errors='replace')
        print(f"Decrypted text: {repr(decoded_text)}")
        print(f"Readable: {decoded_text}")
    except Exception as e:
        print(f"Decoding error: {e}")
        print(f"As hex: {bytes(decrypted_bytes).hex()}")
        printable_chars = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in decrypted_bytes)
        print(f"Printable chars: {printable_chars}")

if __name__ == "__main__":
    main()
