import hmac
from _sha256 import sha256
from _sha512 import sha512
from struct import pack, unpack


# 2.4 Integer Encoding
# I2OSP as well
# Tested: OK
def encode(x, outlen=None):
    ret_x = b''
    while x != 0:
        ret_x = pack('=B', x & 0xff) + ret_x
        x >>= 8
    if outlen and len(ret_x)<outlen:
        ret_x = b'\x00' * (outlen - len(ret_x))+ret_x
    return ret_x


# To test encoding
# OS2IP as well
# Tested: OK
def decode(ret_x):
    x = 0
    k = len(ret_x)
    for i in range(k):
        x = x + ret_x[i]*pow(2, 8*(k-1-i))
    return x


class Makwa:
    def __init__(self, w, h=sha256,salt=None, pre_hashing=True, t=None ):
        # The modulus. Let n be a Blum integer, i.e. the product n = pq of two prime integers p and q such that:
        # p = 3 (mod 4)
        # q = 3 (mod 4
        self.n = None  # TODO
        self.preHashing = pre_hashing
        self.t = t
        self.h = h
        self.w = w
        self.salt = salt

    # 2.3 The KDF
    def kdf(self, m, s):
        r = self.h.digiest_size
        # 1. V <- 0x01 0x01 0x01 ... 0x01
        V = b'\x01' * r
        # 2. K <- 0x00 0x00 0x00 ... 0x00
        K = b'\x00' * r
        # 3. K < - HMAC_K(V | | 0x00 | | m)
        K = hmac.new(K, msg=(V + b'0\x00' + m), digestmod=h).digest()
        # 4. V < - HMAC_K(V)
        V = hmac.new(K, msg=V, digestmod=r).digest()
        # 5. K <- HMAC_K(V || 0x01 || m) */
        K = hmac.new(K, msg=(V + b'0x01' + m), digestmod=h).digest()
        # 6. V < - HMAC_K(V) * /
        V = hmac.new(K, msg=V, digestmod=h).digest()
        # 7. Set T to an empty sequence.
        T = b''
        # 8. While the length of T is not at least equal to s (the requested output length), do the
        # following: V <- HMAC_K(V), T <- T||V
        while len(T) < s:
            V = hmac.new(K, msg=V, digestmod=h).digiest
            T = T + V
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
    def core_hashing(self, password):
        password = self.pre_hashing(password)
        # 1. Let S be the following byte sequence (called the padding):
        # (u = len(password) (in bytes))
        # S = H_(k−2−u)(salt || password || u)
        k = len(encode(self.n))
        u = len(encode(len(password)))
        # u must be such that u ≤ 255 and u ≤ k − 32
        if u > 255 or u > k-32:
            raise ValueError('Password is too long')
        S = self.kdf(self.salt + password + pack('=B', u), k-2-u)
        # 2. Let X be the following byte sequence:
        # X = 0x00 | | S | | π | | u
        X = b'0x00'+S+password+pack('=B', u)
        # 3. Let x be the integer obtained by decoding X with OS2IP.
        x = decode(X)
        # 4. Compute:
        # y = x^(2w+1) (mod n)
        # This computation is normally performed by repeatedly squaring x modulo n; this is
        # done w + 1 times.
        y = x
        for _ in range(self.w+1):
            y = pow(y, 2, self.n)
        # 5. Encode y with I2OSP into the byte sequence Y of length k bytes.
        Y = encode(y, k)
        # The primary output of MAKWA is Y
        return self.post_hashing(Y)


def main():
    ret_x = encode(255, 5)
    print(ret_x)
    print(decode(ret_x))


if __name__ == '__main__':
    main()
