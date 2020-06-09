import os
import random
from binascii import hexlify
from encoding import encode, bytes_to_str, decode
from modInverse import modInverse
MAGIC_PRIVKEY = 0x55414D31
MAGIC_PRIVKEY_WITHGEN = 0x55414D71
MAGIC_PUBKEY = 0x55414D30
MAGIC_PUBKEY_WITHGEN = 0x55414D70
PSP = 307444891294245705

def getMagic(encoded):
    hexs = (hexlify(encoded[0:4]))
    magic = int(hexs, 16)
    return magic

def computeNumMR(k):
    if k < 400:
        if k<250:
            if k<100:
                return 40
            elif k <150:
                return 27
            elif k <200:
                return 18
            else:
                return 15
        else:
            if k < 300:
                return 12
            elif k < 350:
                return 9
            else:
                return 8
    else:
        if k<650:
            if k<450:
                return 7
            elif k <550:
                return 6
            else:
                return 5
        else:
            if k < 850:
                return 4
            elif k < 1300:
                return 3
            else:
                return 2


def isMultipleSmallPrime(x):
    if x < 0:
        x = -x
    if x == 0:
        return True
    if (x & (1 << 0)) == 0: # checkout BigInteger.testBit in java
        return True
    a = PSP
    b = x % PSP
    while b != 0:
        t = a % b
        a = b
        b = t
    return a != 1

def makeRandNonZero(m):
    if m <= 1:
        raise ValueError('Invalid modulus (less than 2)')
    z = random.randrange(1,m)
    return z

def passesMR(n,cc):
    if n<0:
        n = -n
    if n == 0:
        return True
    if n.bit_length() <= 3:
        if n == 2 or n == 3 or n == 5 or n ==7:
            return False
        else:
            return True
    if (n & (1 << 0)) == 0: # checkout BigInteger.testBit in java
        return True

    # Miller-Rabin algorithm
    nm1 = n - 1
    nm2 = nm1 - 1
    r = nm1
    s = 0
    while (r & (1 << 0)) == 0:
        s+=1
        r = r >> 1
    while cc > 0:
        cc-=1
        a = makeRandNonZero(nm2) + 1
        y = pow(a,r,n)
        if y!=1 and y!=nm1:
            for j in range(1,s):
                if y == nm1:
                    break
                y = (y * y) % n
                if y == 1:
                    return False
            if y!=nm1:
                return False
    return True


def generatePrvateKey(size):
    if size < 1273 or size > 32768:
        raise ValueError('Invalid modulus size: '+str(size))
    k = (size - 14) // 4
    x = 0
    case = (size-14) & 3
    if case == 0:
        x = 7
    elif case == 1:
        x = 8
    elif case == 2:
        x = 10
    else:
        x = 12
    sp = []
    used = []
    bp = []
    length = (k+12) >> 3
    mz16 = 0xFFFF >> (8 * length - k)
    mo16 = x << (k + 16 - 8 * length)
    numMR = computeNumMR(k)
    numMR2 = computeNumMR(k << 1)
    flag = True
    while flag:
        buf = os.urandom(length)
        buf = encode(buf[0] & (mz16 >> 8), 1) + buf[1:]
        buf = encode(buf[0], 1) + encode(buf[1] & mz16,1) + buf[2:]
        buf = encode(buf[0] | (mo16 >> 8), 1) + buf[1:]
        buf = encode(buf[0], 1) + encode(buf[1] | mo16,1) + buf[2:]
        buf = buf[:(length-1)] + encode(buf[length - 1] | 0x01)
        pj = decode(buf)
        if isMultipleSmallPrime(pj):
            continue
        if not passesMR(pj, numMR):
            continue
        flag1=False
        flag2=False
        for z in sp:
            if z == pj:
                flag1 = True
                break
        if flag1:
            continue
        for i in range(len(sp)-1,-1,-1):
            if used[i]:
                continue
            pi = sp[i]
            p = ((pi * pj) << 1) + 1
            if not passesMR(p,numMR2):
                continue
            if pow(4, pi, p) == 1:
                continue
            if pow(4, pj, p) == 1:
                continue
            bp.append(p)
            if len(bp) == 2:
                flag = False
                break
            sp.append(pj)
            used.append(True)
            used[i] = True
            flag2 = True
            break
        if not flag:
            break
        if flag2:
            continue
        sp.append(pj)
        used.append(False)
    p = bp[0]
    q = bp[1]
    if p < q:
        t = p
        p = q
        q = t
    mk = MakwaPrivateKey(p, q, 4)
    if mk.modulus.bit_length() != size:
        raise ValueError('Key generation error')
    return mk

def makeMakwaPrivateKey(encoded):
    magic = getMagic(encoded)
    withgen = False
    qgenlen = 0
    readlen = 0
    p = None
    q = None
    qgen = None
    if magic == MAGIC_PRIVKEY_WITHGEN:
        withgen = True
    if magic == MAGIC_PRIVKEY or magic == MAGIC_PRIVKEY_WITHGEN:
        readlen += 4
        plen = int(hexlify(encoded[readlen:readlen + 2]), 16)
        readlen += 2
        p = int(hexlify(encoded[readlen:readlen + plen]), 16)
        readlen += plen
        qlen = int(hexlify(encoded[readlen:readlen + 2]), 16)
        readlen += 2
        q = int(hexlify(encoded[readlen:readlen + qlen]), 16)
        readlen += qlen
        if withgen:
            qgenlen = int(hexlify(encoded[readlen:readlen + 2]), 16)
            readlen += 2
            qgen = int(hexlify(encoded[readlen:readlen + qgenlen]), 16)
            readlen += qgenlen
        if readlen < len(encoded):
            raise ValueError('Trailing garbage')
    else:
        raise ValueError('Not a Makwa private key')
    Mak = MakwaPrivateKey(p, q, qgen)
    return Mak


def encodePublic(modulus, QRGen = None):
    modulus_e = encode(modulus)
    modulus_e_len = encode(len(modulus_e), 2)
    qrgen_e = None
    qrgen_e_len = None
    header = encode(MAGIC_PUBKEY)
    if QRGen is not None:
        qrgen_e = encode(QRGen)
        qrgen_e_len = encode(len(qrgen_e), 2)
        header = encode(MAGIC_PUBKEY_WITHGEN)
    ret = header + modulus_e_len + modulus_e
    if QRGen is not None:
        ret += qrgen_e_len + qrgen_e
    return ret


def decodePublic(encoded):
    magic = getMagic(encoded)
    modulus_len = None
    modulus = None
    withgen = False
    qgen = None
    readlen = 0
    if magic == MAGIC_PUBKEY_WITHGEN:
        withgen = True
    if magic == MAGIC_PUBKEY or magic == MAGIC_PUBKEY_WITHGEN:
        readlen += 4
        modulus_len = int(hexlify(encoded[readlen:readlen + 2]), 16)
        readlen += 2
        modulus = int(hexlify(encoded[readlen:readlen + modulus_len]), 16)
        readlen += modulus_len
        if withgen:
            qgenlen = int(hexlify(encoded[readlen:readlen + 2]), 16)
            readlen += 2
            qgen = int(hexlify(encoded[readlen:readlen + qgenlen]), 16)
            readlen += qgenlen
        if readlen < len(encoded):
          raise ValueError('Trailing garbage')
    else:
        raise ValueError('Not a Makwa public key')
    return modulus


def encodePrivate(p, q, QRGen = None):
    p_e = encode(p)
    q_e = encode(q)
    p_e_len = encode(len(p_e), 2)
    q_e_len = encode(len(q_e), 2)
    qrgen_e = None
    qrgen_e_len = None
    header = encode(MAGIC_PRIVKEY)
    if QRGen is not None:
        qrgen_e = encode(QRGen)
        qrgen_e_len = encode(len(qrgen_e), 2)
        header = encode(MAGIC_PRIVKEY_WITHGEN)
    ret = header + p_e_len + p_e + q_e_len + q_e
    if QRGen is not None:
        ret += qrgen_e_len + qrgen_e
    return ret


class MakwaPrivateKey:
    def __init__(self, p, q, gen=None):
        if p<0 or q <0 or p & 3 != 3 or q & 3 != 3 or p == q:
            raise ValueError("Invalid Makwa private key")
        self.p = p
        self.q = q
        self.QRGen = gen
        self.modulus = p*q
        if len(encode(self.modulus))*8 < 1273:
            raise ValueError("Invalid Makwa private key")
        if gen is not None and (gen <= 1 or gen >= self.modulus):
            raise ValueError("Invalid Makwa private key")
        self.invQ = modInverse(q, p)

    def exportPublic(self):
        return encodePublic(self.modulus, self.QRGen)

    def exportPrivate(self):
        return encodePrivate(self.p, self.q, self.QRGen)


def main():
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
    print('MoInverse(7,20): '+str(modInverse(7, 20)))
    mpriv = makeMakwaPrivateKey(PRIV2048)
    print('Modulus from priv: '+bytes_to_str(encode(mpriv.modulus)))
    print('Modulus from exported public: '+bytes_to_str(encode(decodePublic(mpriv.exportPublic()))))
    print('Exported public: '+bytes_to_str(mpriv.exportPublic()))
    print('Exported priv: '+bytes_to_str(mpriv.exportPrivate()))
    mpriv_gen = generatePrvateKey(2048)
    print('Generated private: '+bytes_to_str(mpriv_gen.exportPrivate()))


if __name__ == '__main__':
    main()
