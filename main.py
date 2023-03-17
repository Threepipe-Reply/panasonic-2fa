import base64
import hmac
import struct
import time
import calendar
import threading


def interval(secret):
    threading.Timer(30.0, interval, args=[secret]).start()
    code_from_secret(secret)


def code_from_secret(secret):
    secret = secret.upper()
    secret = base64.b32decode(secret)  # Decode the base32-encoded secret.
    timestamp = calendar.timegm(
        time.gmtime()) // 30  # Get the timestamp in seconds since the UNIX epoch and convert it to a byte string.
    msg = struct.pack(">Q", timestamp)
    key = hmac.new(secret, msg,
                   digestmod="sha1").digest()  # Generate an HMAC-SHA1 hash using the secret and the timestamp.
    offset = key[-1] & 0xF  # Get the offset value from the last 4 bits of the hash.
    truncated_hash = key[offset:offset + 4]  # Get the 4 bytes of the hash starting at the offset.
    code = struct.unpack(">L", truncated_hash)[0]  # Convert the 4 bytes to an unsigned integer.
    code &= 0x7FFFFFFF  # Mask the integer to get only the 31 least significant bits.
    code %= 1000000  # Limit the integer to 6 digits.
    return f"{code:06}"


# cached lookup table
BASE32_LOOKUP_TABLE = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11,
                       'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21,
                       'W': 22, 'X': 23, 'Y': 24, 'Z': 25, '2': 26, '3': 27, '4': 28, '5': 29, '6': 30, '7': 31}


def base32_decode(b32):
    b32 = b32.upper()
    l = len(b32)
    n = 0
    j = 0
    binary = bytearray()
    for i in range(l):
        n = n << 5
        n += BASE32_LOOKUP_TABLE[b32[i]]
        j += 5
        if j >= 8:
            j -= 8
            binary.append(n & 0xFF)
            n >>= 8
    return bytes(binary)
