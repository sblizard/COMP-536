from typing import List

def load_ciphertexts() -> List[bytes]:
    """
    Reads texts.txt where ciphertext blocks are separated by blank lines.
    If a block has multiple non-blank lines, we keep ONLY the last line (assumed ciphertext hex).
    Returns: list[bytes]
    """
    ciphertext_hex_strings = []
    current_block = []
    with open("texts.txt", "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line:
                if current_block:
                    ciphertext_hex_strings.append(current_block[-1])
                    current_block = []
                continue
            current_block.append(line)
        if current_block:
            ciphertext_hex_strings.append(current_block[-1])

    ciphertexts = []
    for block_index, hex_string in enumerate(ciphertext_hex_strings):
        try:
            ciphertexts.append(bytes.fromhex(hex_string))
        except ValueError as e:
            raise ValueError(f"Block {block_index} is not valid hex:\n{hex_string}") from e
    return ciphertexts

def bitwise_xor_with_padding(first_bytes: bytes, second_bytes: bytes) -> bytes:
    """XOR up to the length of the longer input, padding the shorter with zeros."""
    max_length = max(len(first_bytes), len(second_bytes))
    result = bytearray(max_length)
    for index in range(max_length):
        first_byte = first_bytes[index] if index < len(first_bytes) else 0
        second_byte = second_bytes[index] if index < len(second_bytes) else 0
        result[index] = first_byte ^ second_byte
    return bytes(result)

def main():
    ciphertexts = load_ciphertexts()

    # sanity check
    for ciphertext_index, ciphertext in enumerate(ciphertexts):
        if any(bitwise_xor_with_padding(ciphertext, ciphertext)):
            raise RuntimeError(f"Sanity check failed at index {ciphertext_index}")

    for first_index, first_ciphertext in enumerate(ciphertexts):
        for second_index, second_ciphertext in enumerate(ciphertexts):
            xor_result = bitwise_xor_with_padding(first_ciphertext, second_ciphertext)
            print(f"Text {first_index} XOR Text {second_index} =")
            print(xor_result.hex(), end="\n\n")

if __name__ == "__main__":
    main()
