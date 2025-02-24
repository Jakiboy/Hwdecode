from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import html
import argparse

BLOCKSIZE = 0x14
PASSWORD = "6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498"

def write_uint32_le(buffer, value, offset):
    """Write a 32-bit unsigned integer in little-endian format to a bytearray."""
    for i in range(4):
        buffer[offset + i] = value & 0xFF
        value >>= 8

def decode_aes_string_to_buffer(encrypted_str):
    """Decodes an encoded string into a binary buffer."""
    buf = bytearray([ord(c) for c in encrypted_str])
    for i in range(len(buf)):
        if buf[i] == 0x7E:  # character ~
            buf[i] = 0x1E
        else:
            buf[i] -= 0x21  # character !
    return buf

def encode_aes_buffer_to_long(buffer):
    """Convert a sequence of 5 values into a single numeric value using a weighted sum."""
    output = 0
    v3 = 1
    for i in range(5):
        output += v3 * buffer[i]
        v3 *= 0x5D
    return output

def plain_to_bin(buffer):
    """Convert plain string in buffer to binary."""
    if len(buffer) % 5 != 0:
        return None

    output = bytearray(len(buffer) * 4 // 5)
    period_five = 0
    for i in range(0, len(output), 4):
        _long = encode_aes_buffer_to_long(buffer[period_five:period_five + 5])
        write_uint32_le(output, _long, i)
        period_five += 5
    return output

def format_encrypted_str(encrypted_str):
    """Format & check encrypted string."""
    if len(encrypted_str) < 3:
        return ''

    if encrypted_str[0] != "$" or encrypted_str[1] != "2" or encrypted_str[-1] != "$":
        return ''

    return encrypted_str[2:-1]

def to_hex_string(bytes_data):
    """Convert bytes to a HEX string."""
    return ''.join(f"{byte:02x}" for byte in bytes_data)

def decrypt(input_data, key):
    """Decrypt string, encrypted by Huawei router."""
    if not isinstance(input_data, (bytearray, str)):
        return ''

    if not isinstance(key, (bytearray, str)):
        return ''

    if isinstance(key, bytearray):
        key = to_hex_string(key)

    # Decode HTML entities (e.g., &lt; to <, &amp; to &, &apos; to ')
    input_data = html.unescape(input_data)

    formatted_str = format_encrypted_str(input_data)
    if not formatted_str:
        return ''

    unvisible = decode_aes_string_to_buffer(formatted_str)
    block_count = len(unvisible) // BLOCKSIZE
    if len(unvisible) != BLOCKSIZE * block_count:
        return ''

    iv = plain_to_bin(unvisible[block_count * BLOCKSIZE - BLOCKSIZE:block_count * BLOCKSIZE])
    data_all = plain_to_bin(unvisible[:block_count * BLOCKSIZE - BLOCKSIZE])

    if not iv or not data_all:
        return ''

    # AES decryption
    try:
        cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, iv=bytes(iv))
        decrypted_data = cipher.decrypt(bytes(data_all))

        # Try to unpad the data
        try:
            decrypted_data = unpad(decrypted_data, AES.block_size)
        except ValueError:
            # If padding is incorrect, return raw decrypted data
            pass

        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError, UnicodeDecodeError):
        return ''

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Decrypt a cipher encrypted by a Huawei router.")
    parser.add_argument("cipher", nargs="?", type=str, help="The encrypted cipher string to decrypt.")
    args = parser.parse_args()

    # If no argument is provided, prompt the user for input
    if args.cipher is None:
        cipher = input("Enter the encrypted cipher: ")
    else:
        cipher = args.cipher

    # Decrypt the cipher
    decrypted_result = decrypt(cipher, PASSWORD)
    if decrypted_result:
        print(decrypted_result)
    else:
        print("Error: Failed to decrypt the cipher")

if __name__ == "__main__":
    main()