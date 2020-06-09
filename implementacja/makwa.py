import base64
import hmac
from hashlib import sha256
from hashlib import sha512
from struct import pack

from encoding import decode, encode, bytes_to_str, base64_custom_en
from makwakeys import MAGIC_PUBKEY, MAGIC_PUBKEY_WITHGEN, MAGIC_PRIVKEY, MAGIC_PRIVKEY_WITHGEN, getMagic, \
    makeMakwaPrivateKey, decodePublic


def makeMakwa(encoded, h=sha256, pre_hashing=True, t=0, w=4096):
    magic = getMagic(encoded)
    makwa = None
    if magic == MAGIC_PRIVKEY or magic == MAGIC_PRIVKEY_WITHGEN:
        mpriv = makeMakwaPrivateKey(encoded)
        makwa = Makwa(mpriv.modulus, h, pre_hashing, t, w)
    elif magic == MAGIC_PUBKEY or magic == MAGIC_PUBKEY_WITHGEN:
        n = decodePublic(encoded)
        makwa = Makwa(n, h, pre_hashing, t, w)
    return makwa


def square_root_mod(d, p):
    return pow(d, (p + 1) / 4) % p


def chinese_remainder(p, q, iq, yp, yq):
    h = ((yp - yq) * iq) % p
    y = yq + (q * h)
    return y


def sqrtExp(p, w):
    e = (p + 1) >> 2
    return pow(e, w, p - 1)


def unescrow(privateKey, hashed, salt, hashFunction, workFactor):
    mpriv = makeMakwaPrivateKey(privateKey)
    y = decode(hashed)
    p = mpriv.p
    q = mpriv.q
    iq = mpriv.invQ
    ep = sqrtExp(p, workFactor + 1)
    eq = sqrtExp(q, workFactor + 1)
    x1p = pow((y % p), ep, p)
    x1q = pow((y % q), eq, q)
    x2p = (p - x1p) % p
    x2q = (q - x1q) % q
    xc = [0] * 4
    xc[0] = chinese_remainder(p, q, iq, x1p, x1q)
    xc[1] = chinese_remainder(p, q, iq, x1p, x2q)
    xc[2] = chinese_remainder(p, q, iq, x2p, x1q)
    xc[3] = chinese_remainder(p, q, iq, x2p, x2q)
    for i in range(4):
        buf = encode(xc[i], len(encode(mpriv.modulus)))
        k = len(buf)
        if buf[0] != 0x00:
            continue
        u = buf[k - 1] & 0xFF
        if u > (k - 32):
            continue
        tmp = salt + buf[k-1-u:k]
        S = Makwa(mpriv.modulus, hashFunction, False, 0, workFactor).kdf(tmp, k - u - 2)
        pi = buf[k - 1 - u:k - 1]
        flag = False
        for j in range(len(S)):
            if S[j] != buf[j + 1]:
                flag = True
                break
        if flag:
            continue
        pi = buf[k - 1 - u:k - 1]
        return pi


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
        self.mod_id = self.kdf(encode(n), 8)

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
        # 6. V < - HMAC_K(V)
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
        if self.t != 0:
            return self.kdf(hash, self.t)
        else:
            return hash

    # 2.6 Core Hashing
    # Basic Test: OK
    def hash(self, password, salt):
        password = self.pre_hashing(password)
        # 1. Let S be the following byte sequence (called the padding):
        # (u = len(password) (in bytes))
        # S = H_(k−2−u)(salt || password || u)
        k = len(encode(self.n))
        u = len(password)
        # u must be such that u ≤ 255 and u ≤ k − 32
        if u > 255 or u > k - 32:
            raise ValueError('Password is too long')
        S = self.kdf(salt + password + pack('=B', u), k - 2 - u)
        # 2. Let X be the following byte sequence:
        # X = 0x00 | | S | | π | | u
        X = b'\x00' + S + password + pack('=B', u)
        # 3. Let x be the integer obtained by decoding X with OS2IP.
        x = decode(X)
        # 4. Compute:
        # y = x^(2^(w+1)) (mod n)
        # This computation is normally performed by repeatedly squaring x modulo n; this is
        # done w + 1 times.
        y = x
        for _ in range(self.w + 1):
            y = pow(y, 2, self.n)
        # 5. Encode y with I2OSP into the byte sequence Y of length k bytes.
        Y = encode(y, k)
        # The primary output of MAKWA is Y
        return self.post_hashing(Y)

    def check(self, ref, hashed):
        return ref == hashed

    def encode_output(self, salt, pre_hash, post_hash_len, wf, tau):
        out = ""  # starting string
        out += base64_custom_en(self.mod_id, False)
        out += "_"
        # pre-/post-hashing flag
        if pre_hash:
            if post_hash_len > 0:
                out += "b"  # pre: yes, post: yes
            else:
                out += "r"  # pre: yes, post: no
        else:
            if post_hash_len > 0:
                out += "s"  # pre: no, post: yes
            else:
                out += "n"  # pre: no, post: no
        wf_proc = wf
        j = 0
        # ensure wf = (2 or 3)*2^j, where j is an integer
        while wf_proc > 3 and (wf & 1) == 0:
            wf_proc = wf_proc // 2
            j += 1
            if wf_proc == 2 or wf_proc == 3:
                out += str(wf_proc)
                if j < 10:
                    j = '0'+str(j)
                    out += j
                else:
                    out += str(j)
        out += '_'
        out += base64_custom_en(salt, False)
        out += "_"
        out += base64_custom_en(tau, False)
        return out


def main():
    ret_x = encode(255, 5)
    # print(ret_x)
    # print(decode(ret_x))
    # print(int('55' '22', 16))
    PRIV2048 = bytes.fromhex(
        '55' '41' '4d' '31' '00' '80'
        'ea' '43'
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
    )

    PUB2048 = bytes.fromhex(
        '55' '41' '4d' '30' '01' '00'
        'c2' '2c'
        '40' 'bb' 'd0' '56'
        'bb' '21' '3a' 'ad'
        '7c' '83' '05' '19'
        '10' '1a' 'b9' '26'
        'ae' '18' 'e3' 'e9'
        'fc' '96' '99' 'c8'
        '06' 'e0' 'ae' '5c'
        '25' '94' '14' 'a0'
        '1a' 'c1' 'd5' '2e'
        '87' '3e' 'c0' '80'
        '46' 'a6' '8e' '34'
        '4c' '8d' '74' 'a5'
        '08' '95' '28' '42'
        'ef' '0f' '03' 'f7'
        '1a' '6e' 'dc' '07'
        '7f' 'aa' '14' '89'
        '9a' '79' 'f8' '3c'
        '3a' 'e1' '36' 'f7'
        '74' 'fa' '6e' 'b8'
        '8f' '1d' '1a' 'ea'
        '5e' 'a0' '2f' 'c0'
        'cc' 'af' '96' 'e2'
        'ce' '86' 'f3' '49'
        '0f' '49' '93' 'b4'
        'b5' '66' 'c0' '07'
        '96' '41' '47' '2d'
        'ef' 'c1' '4b' 'ec'
        'cf' '48' '98' '4a'
        '79' '46' 'f1' '44'
        '1e' 'a1' '44' 'ea'
        '4c' '80' '2a' '45'
        '75' '50' 'ba' '3d'
        'f0' 'f1' '4c' '09'
        '0a' '75' 'fe' '9e'
        '6a' '77' 'cf' '0b'
        'e9' '8b' '71' 'd5'
        '62' '51' 'a8' '69'
        '43' 'e7' '19' 'd2'
        '78' '65' 'a4' '89'
        '56' '6c' '1d' 'c5'
        '7f' 'cd' 'ef' 'ac'
        'a6' 'ab' '04' '3f'
        '8e' '13' 'f6' 'c0'
        'be' '7b' '39' 'c9'
        '2d' 'a8' '6e' '1d'
        '87' '47' '7a' '18'
        '9e' '73' 'ce' '8e'
        '31' '1d' '3d' '51'
        '36' '1f' '8b' '00'
        '24' '9f' 'b3' 'd8'
        '43' '56' '07' 'b1'
        '4a' '1e' '70' '17'
        '0f' '9a' 'f3' '67'
        '84' '11' '0a' '3f'
        '2e' '67' '42' '8f'
        'c1' '8f' 'b0' '13'
        'b3' '0f' 'e6' '78'
        '2a' 'ec' 'b4' '42'
        '8d' '7c' '8e' '35'
        '4a' '0f' 'bd' '06'
        '1b' '01' '91' '7c'
        '72' '7a' 'be' 'e0'
        'fe' '3f' 'd3' 'ce'
        'f7' '61'
    )
    M256 = makeMakwa(PRIV2048, sha256, False, 0, 1024)
    M512 = makeMakwa(PRIV2048, sha512, False, 0, 1024)
    M256Pub = makeMakwa(PUB2048, sha256, False, 0, 4096)
    # Sample KDF test
    print('\nSample KDF test')
    print(bytes_to_str(M256.kdf(b'\x07', 100)))
    print(bytes_to_str(M512.kdf(b'\x07', 100)))

    # Sample password hashing test
    salt = bytes.fromhex(
        'C7' '27' '03' 'C2'
        '2A' '96' 'D9' '99'
        '2F' '3D' 'EA' '87'
        '64' '97' 'E3' '92'
    )
    ref = bytes.fromhex(
        'C9' 'CE' 'A0' 'E6'
        'EF' '09' '39' '3A'
        'B1' '71' '0A' '08'
    )
    salt0 = bytes.fromhex(
        'b8' '2c' 'b4' '2e'
        '3a' '2d' 'fc' '2a'
        'd6' '0b' '8b' '76'
        'c6' '66' 'b0' '15'
    )
    print(encode(2, 50))
    print('\nSample password hashing test')
    password = "Gego beshwaji'aaken awe makwa; onzaam naniizaanizi."
    pwd_bytes = bytes(password, 'UTF-8')
    hashed = M256Pub.hash(pwd_bytes, salt)
    print("Salt= " + bytes_to_str(salt))
    print("Ref= " + bytes_to_str(ref))
    print("Hashed= " + bytes_to_str(hashed))
    print(decodePublic(PUB2048) == makeMakwaPrivateKey(PRIV2048).modulus)
    hashed2 = makeMakwa(PRIV2048, sha256, False, 0, 4096).hash(pwd_bytes, salt0)
    print(unescrow(PRIV2048, hashed2, salt0, sha256, 4096))


if __name__ == '__main__':
    main()
