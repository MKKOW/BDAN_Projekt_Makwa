from binascii import hexlify
from encoding import encode, bytes_to_str
from modInverse import modInverse
MAGIC_PRIVKEY = 0x55414D31
MAGIC_PRIVKEY_WITHGEN = 0x55414D71
MAGIC_PUBKEY = 0x55414D30
MAGIC_PUBKEY_WITHGEN = 0x55414D70

def makeMakwaPrivateKey(encoded):
    hexs = (hexlify(encoded[0:4]))
    magic = int(hexs, 16)
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
    Mak = MakwaPrivateKey(p,q, qgen)
    return Mak


def encodePublic(modulus, QRGen = None):
    modulus_e = encode(modulus)
    modulus_e_len = encode(len(modulus_e))
    qrgen_e = None
    qrgen_e_len = None
    header = encode(MAGIC_PUBKEY)
    if QRGen is not None:
        qrgen_e = encode(QRGen)
        qrgen_e_len = encode(len(qrgen_e))
        header = encode(MAGIC_PUBKEY_WITHGEN)
    ret = header + modulus_e_len + modulus_e
    if QRGen is not None:
        ret += qrgen_e_len + qrgen_e
    return ret


def decodePublic(encoded):
    hexs = (hexlify(encoded[0:4]))
    magic = int(hexs, 16)
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
    print(modInverse(7, 20))
    mpriv = makeMakwaPrivateKey(PRIV2048)
    print(bytes_to_str(encode(mpriv.modulus)))
    print(bytes_to_str(encode(decodePublic(mpriv.exportPublic()))))


if __name__ == '__main__':
    main()
