import hmac
from hashlib import sha256
from hashlib import sha512
from struct import pack, unpack


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


# def makwaPrivateKey(encoded):
class Makwa:
    # n - modulus, h - hash function, t - post_hashing length, w - work factor
    def __init__(self, n, h=sha256, pre_hashing=True, t=0, w=4096):
        # The modulus. Let n be a Blum integer, i.e. the product n = pq of two prime integers p and q such that:
        # p = 3 (mod 4)
        # q = 3 (mod 4
        self.n = n
        self.preHashing = pre_hashing
        self.t = t
        self.h = h
        self.w = w
        self.salt = b''

    # 2.3 The KDF
    # Tested: OK
    def kdf(self, m, s):
        r = 32
        if self.h == sha256:
            r = 32
        if self.h == sha512:
            r = 64
        # 1. V <- 0x01 0x01 0x01 ... 0x01
        V = b'\x01' * r
        # 2. K <- 0x00 0x00 0x00 ... 0x00
        K = b'\x00' * r
        # 3. K < - HMAC_K(V | | 0x00 | | m)
        K = hmac.new(K, msg=(V + b'\x00' + m), digestmod=self.h).digest()
        # 4. V < - HMAC_K(V)
        V = hmac.new(K, msg=V, digestmod=self.h).digest()
        # 5. K <- HMAC_K(V || 0x01 || m)
        K = hmac.new(K, msg=(V + b'\x01' + m), digestmod=self.h).digest()
        # 6. V < - HMAC_K(V) * /
        V = hmac.new(K, msg=V, digestmod=self.h).digest()
        # 7. Set T to an empty sequence.
        T = b''
        # 8. While the length of T is not at least equal to s (the requested output length), do the
        # following: V <- HMAC_K(V), T <- T||V
        while len(T) < s:
            V = hmac.new(K, msg=V, digestmod=self.h).digest()
            T += V
        # The output Hs(m) then consists in the s leftmost bytes of T.
        return T[:s]

    # 2.5 Input Pre-Hashing
    def pre_hashing(self, password):
        if self.preHashing:
            return self.kdf(password, 64)
        else:
            return password

    # 2.7 Post-Hashing
    def post_hashing(self, hash):
        if self.t is not None:
            return self.kdf(hash, self.t)
        else:
            return hash

    # 2.6 Core Hashing
    def hash(self, password):
        password = self.pre_hashing(password)
        # 1. Let S be the following byte sequence (called the padding):
        # (u = len(password) (in bytes))
        # S = H_(k−2−u)(salt || password || u)
        k = len(encode(self.n))
        u = len(encode(len(password)))
        # u must be such that u ≤ 255 and u ≤ k − 32
        if u > 255 or u > k - 32:
            raise ValueError('Password is too long')
        S = self.kdf(self.salt + password + pack('=B', u), k - 2 - u)
        # 2. Let X be the following byte sequence:
        # X = 0x00 | | S | | π | | u
        X = b'0x00' + S + password + pack('=B', u)
        # 3. Let x be the integer obtained by decoding X with OS2IP.
        x = decode(X)
        # 4. Compute:
        # y = x^(2w+1) (mod n)
        # This computation is normally performed by repeatedly squaring x modulo n; this is
        # done w + 1 times.
        y = x
        for _ in range(self.w + 1):
            y = pow(y, 2, self.n)
        # 5. Encode y with I2OSP into the byte sequence Y of length k bytes.
        Y = encode(y, k)
        # The primary output of MAKWA is Y
        return self.post_hashing(Y)


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


def main():
    ret_x = encode(255, 5)
    print(ret_x)
    print(decode(ret_x))
    print(int('55' '22', 16))
    PRIV2048 = int(
        '55' '41' '4d' '31'
        '00' '80' 'ea' '43'
        'd7' '9d' 'f0' 'b8'
        '74' '14' '0a' '55'
        'ec' 'd1' '44' '73'
        '2e' 'af' '49' 'd9'
        'c8' 'f0' 'e4' '37'
        '6f' '5d' '72' '97'
        '2a' '14' '66' '79'
        'e3' '82' '44' 'f5'
        'a9' '6e' 'f5' 'ce'
        '92' '8a' '54' '25'
        '12' '40' '47' '5f'
        'd1' 'dd' '96' '8b'
        '9a' '77' 'ad' 'd1'
        '65' '50' '56' '4c'
        '1d' 'd2' '42' '40'
        '08' 'ea' '83' 'c2'
        '59' 'd5' '3b' '88'
        '61' 'c5' 'e9' '4f'
        '22' '8f' '03' 'c4'
        '98' 'dd' '3c' '8c'
        '69' '49' 'e3' '66'
        '02' 'fe' '74' '6d'
        '64' 'd5' '14' '89'
        'c7' '6c' '74' 'db'
        'c2' '44' '7e' '22'
        '2e' 'cf' '28' 'fa'
        '9b' 'd4' '4e' '81'
        '41' '07' '55' '87'
        '9e' '71' 'bd' 'f8'
        'fb' '4a' '61' 'd8'
        'ad' '3d' 'f4' '4f'
        'fc' '9b' '00' '80'
        'd4' '30' '28' 'ee'
        '37' '4f' 'eb' 'b9'
        '3b' '5d' 'f8' 'dc'
        '1c' '68' '37' '13'
        'ab' '05' '10' 'af'
        '7e' 'eb' 'e6' '3d'
        '33' 'f9' '0a' 'f7'
        '63' 'fa' '22' '64'
        'b6' '8b' '09' '21'
        '94' '90' 'a5' 'a5'
        '64' '4d' '63' '56'
        '85' '9c' '27' 'cd'
        'f9' '76' '71' '12'
        '2e' '4d' '9a' '13'
        'd9' '16' '09' '60'
        '9c' '46' '90' '14'
        'da' 'e3' '0f' '9a'
        'e6' 'bc' '93' '78'
        'e7' '97' '47' '60'
        '1e' 'ee' 'a8' '18'
        '46' '98' '42' '72'
        '08' '9c' '08' '53'
        '49' '7f' 'c5' '3a'
        '51' 'd4' '5d' '37'
        'f0' 'cb' '4e' '67'
        'd8' 'b9' '59' '21'
        'b7' 'd2' '93' 'd7'
        '55' 'b4' '9d' 'da'
        '55' 'b8' '15' '29'
        'a7' '06' 'cd' '67'
        'ee' '3b' 'fe' 'fe'
        'c4' 'f3' 'f5' 'b3'
        , 16)
    M256 = Makwa(PRIV2048, sha256, False, 0, 1024)
    M512 = Makwa(PRIV2048, sha512, False, 0, 1024)
    print(bytes_to_str(M256.kdf(b'\x07', 100)))  # Sample KDF test
    print(bytes_to_str(M512.kdf(b'\x07', 100)))


if __name__ == '__main__':
    main()
