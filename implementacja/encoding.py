from struct import pack
from math import ceil
import base64

# 2.4 Integer Encoding
# I2OSP as well
# Tested: OK
def encode(x, outlen=None):
    ret_x = b''
    while x != 0:
        ret_x = pack('=B', x & 0xff) + ret_x
        x >>= 8
    if outlen and len(ret_x) < outlen:
        ret_x = b'\x00' * (outlen - len(ret_x)) + ret_x
    return ret_x


# To test encoding
# OS2IP as well
# Tested: OK
def decode(ret_x):
    x = 0
    k = len(ret_x)
    for i in range(k):
        x = x + ret_x[i] * pow(2, 8 * (k - 1 - i))
    return x


# Used only for formatting
def byte_to_str(i):
    if i == b'\x00' or i is None:
        return '00'
    ret = ''
    ret = str(hex(i))
    ret = ret[2:]
    if len(ret) == 1:
        ret = '0' + ret
    return ret


# Used only for formatting
def bytes_to_str(x):
    ret = ''
    for i in x:
        ret += byte_to_str(i)
    return ret


# Base64 encoding without newlines or equality signs
def base64_custom_en(buf, with_equal):
    BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = ""
    length = len(buf)
    off = 0
    while length >= 3:
        w = buf[off] & 0xFF
        off += 1
        w = (w << 8) + (buf[off] & 0xFF)
        off += 1
        w = (w << 8) + (buf[off] & 0xFF)
        off += 1
        out += BASE64[w >> 18]
        out += BASE64[(w >> 12) & 0x3F]
        out += BASE64[(w >> 6) & 0x3F]
        out += BASE64[w & 0x3F]
        length -= 3
    if length == 1:
        w1 = buf[off] & 0xFF
        out += BASE64[w1 >> 2]
        out += BASE64[(w1 << 4) & 0x3F]
        if with_equal:
            out += "=="
    elif length == 2:
        w2 = ((buf[off] & 0xFF) << 8) + (buf[off + 1] & 0xFF)
        out += BASE64[w2 >> 10]
        out += BASE64[(w2 >> 4) & 0x3F]
        out += BASE64[(w2 << 2) & 0x3F]
        if with_equal:
            out += "=="
    return out

def base64_custom_de(string, reject_bad, with_equal):
    out = bytearray()
    n = len(string)
    num_eq = int(0)
    acc = int(0)
    k = int(0)
    for i in range(n):
        d = ord(string[i])
        if ord('A') <= d <= ord('Z'):
            d -= ord('A')
        elif ord('a') <= d <= ord('z'):
            d -= ord('a') - 26
        elif ord('0') <= d <= ord('9'):
            d -= ord('0') - 52
        elif d == ord('+'):
            d = 62
        elif d == ord('/'):
            d = 63
        elif d == ord('='):
            if not with_equal or num_eq >= 2:
                raise IOError("unexpected '=' sign")
            num_eq += 1
            d = -1
        else:
            if reject_bad:
                raise ValueError("invalid Base64 string")
            continue
        if d < 0:
            d = 0
        else:
            if num_eq != 0:
                raise ValueError("invalid Base64 termination")
        acc = (acc << 6) + d
        k += 1
        if k == 4:
            out.append(acc // pow(256, 2))
            out.append((acc // 256) % 256)
            out.append(acc % 256)
            acc = 0
            k = 0
    if k != 0:
        if k == 1 or with_equal:
            raise ValueError("truncated base64 input")
        if k == 2:
            out.append(acc // 16)
        if k == 3:
            out.append(acc // 1024)
            out.append(acc // 4 % 256)
    return out


def mpi_en(integer):
    if integer < 0:
        raise ValueError("Cannot encode MPI: negative")
    byte_len = integer.bit_length() / 8
    header_1 = int(ceil((integer.bit_length() / 8) / 256))
    header_2 = int(ceil(integer.bit_length() / 8) % 256)
    length = integer.bit_length()//8
    body = integer.to_bytes(header_1 * 256 + header_2, 'big')
    out = bytearray()

    out += header_1.to_bytes(1, 'big')
    out += header_2.to_bytes(1, 'big')
    out+=(body)
    return out


def mpi_de(byte):
    length = int(byte[0:3], 16)
    buf = byte[4:3+length]  # or (len+4)-1
    return buf
