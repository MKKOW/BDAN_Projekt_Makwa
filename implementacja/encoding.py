from struct import pack
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
