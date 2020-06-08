from struct import pack

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
