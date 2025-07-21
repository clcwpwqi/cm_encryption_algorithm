SEPARATOR = "|"

def _generate_key_stream(key: str, length: int):
    key_codes = [ord(k) for k in key]
    shift_list, xor_list = [], []
    key_len = len(key_codes)
    
    for i in range(length):
        shift = (key_codes[i % key_len] + i) % 31 + 1
        xor_val = (key_codes[(i + 3) % key_len] * i) % 0x10FFFF
        shift_list.append(shift)
        xor_list.append(xor_val)
    
    return shift_list, xor_list

def _rotate_shift(n: int, shift: int) -> int:
    shift = shift % 32
    if shift == 0:
        return n
    if shift > 0:  # Left rotate
        return ((n << shift) | (n >> (32 - shift))) & 0xFFFFFFFF
    else:  # Right rotate (negative shift)
        shift = -shift
        return ((n >> shift) | (n << (32 - shift))) & 0xFFFFFFFF

def encrypt(plaintext: str, key: str) -> str:
    if not key:
        raise ValueError("Key cannot be empty")
    shift_list, xor_list = _generate_key_stream(key, len(plaintext))
    cipher_parts = []
    
    for i, char in enumerate(plaintext):
        codepoint = ord(char)
        shifted = _rotate_shift(codepoint, shift_list[i])
        encrypted = shifted ^ xor_list[i]
        cipher_parts.append(str(encrypted))
    
    return SEPARATOR.join(cipher_parts)

def decrypt(ciphertext: str, key: str) -> str:
    if not key:
        raise ValueError("Key cannot be empty")
    parts = ciphertext.split(SEPARATOR)
    if not parts:
        return ""
        
    shift_list, xor_list = _generate_key_stream(key, len(parts))
    plain_chars = []
    
    for i, part in enumerate(parts):
        encrypted = int(part)
        decrypted = encrypted ^ xor_list[i]
        original = _rotate_shift(decrypted, -shift_list[i])
        plain_chars.append(chr(original))
    
    return "".join(plain_chars)

# 测试
if __name__ == "__main__":
    key = "testkey"
    plaintext = "testtext"
    
    cipher = encrypt(plaintext, key)
    decrypted = decrypt(cipher, key)
    
    print("原文:", plaintext)
    print("密文:", cipher)
    print("解密:", decrypted)
    print("解密成功?", plaintext == decrypted)
