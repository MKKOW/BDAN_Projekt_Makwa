from encoding import mpi_en, bytes_to_str
from makwa import makeMakwa
from makwakeys import makeMakwaPrivateKey, makeRandNonZero, getMagic
from binascii import hexlify
from modInverse import modInverse
from hashlib import sha256
import secrets
MAGIC_DELEG_PARAM = 0x55414D32
MAGIC_DELEG_REQ = 0x55414D33
MAGIC_DELEG_ANS = 0x55414D34
MAGIC_DELEG_PARAM_GEN = 0x55414D40
random_pairs = 1
generator_expand = 2
generator_only = 3

def makeDelegation(encoded):
    readlen = 0
    magic = getMagic(encoded)
    readlen += 4
    with_gen = False
    if magic == MAGIC_DELEG_PARAM_GEN:
        with_gen = True
    if magic == MAGIC_DELEG_PARAM_GEN or magic == MAGIC_DELEG_PARAM:
        modulus_len = int(hexlify(encoded[readlen:readlen + 2]), 16)
        readlen += 2
        modulus = int(hexlify(encoded[readlen:readlen + modulus_len]), 16)
        readlen += modulus_len
        wf = int(hexlify(encoded[readlen:readlen+4]), 16)
        readlen += 4
        num = int(hexlify(encoded[readlen:readlen+2]), 16)

        readlen += 2

        if num < 80 and (num != 1 or not with_gen):
            raise ValueError("Too few mask pairs")
        alpha = [0] * num
        beta = [0] * num
        for i in range(num):
            alpha_len = int(hexlify(encoded[readlen:readlen + 2]), 16)
            readlen += 2
            alpha[i] = int(hexlify(encoded[readlen:readlen+round(alpha_len)]), 16)
            readlen += alpha_len
            beta_len = int(hexlify(encoded[readlen:readlen +2]), 16)
            readlen += 2
            beta[i] = int(hexlify(encoded[readlen:readlen+round(beta_len)]), 16)
            readlen += round(beta_len)
        if readlen < len(encoded):
            raise ValueError('Trailing garbage')
        return Delegation(modulus, wf, alpha, beta, with_gen)
    else:
        raise ValueError("unknown Makwa delegation parameter type")


def generate(mparam, wf, param_type=random_pairs):
    mkw = makeMakwa(mparam, sha256, False, 0, 0)
    mod = mkw.n
    num = 0
    if param_type == random_pairs:
        return generate_rnd_pairs(mkw, wf)
    elif param_type == generator_expand:
        num = mod.bit_length() + 64
    elif param_type == generator_only:
        num = 1
    else:
        raise AttributeError("Uknown parameter")
    qr_gen = makeMakwaPrivateKey(mparam).QRGen
    alpha = [0] * num
    beta = [0] * num
    alpha[0] = qr_gen
    beta[0] = qr_gen
    for i in range(1, num, 1):
        alpha[i] = (pow(alpha[i - 1], 2, mod))
        beta[i] = (pow(beta[i - 1], 2, mod))
    return Delegation(mod, wf, alpha, beta, True)


def generate_rnd_pairs(mkw, wf):
    mod = mkw.n
    num = 300
    alpha = [0] * num
    beta = [0] * num
    b_pow = pow(2, wf)
    for i in range(num):
        r = makeRandNonZero(mod)
        alpha[i] = (r * r % mod)
        beta[i] = modInverse(pow(alpha[i], b_pow), mod)
    return Delegation(mod, wf, alpha, beta, False)

class Delegation:
    # modulus, wf - integers; alpha_arr, beta_arr - integer arrays; with_gen, - boolean
    def __init__(self, modulus, wf, alpha_arr, beta_arr, with_gen):
        if modulus < 0 or modulus.bit_length() < 1273 or modulus & 3 != 1:
            raise ValueError("Invalid modulus")
        if wf < 0:
            raise ValueError("Invalid work factor")
        n = len(alpha_arr)
        if n > 65535 or (n < 80 and n != 1) or n != len(beta_arr):
            raise ValueError("Invalid mask pairs")
        for i in range(n):
            a = alpha_arr[i]
            b = beta_arr[i]
            if a < 0 or b < 0 or a > modulus or b > modulus:
                raise ValueError("Invalid mask value", i)
        self.modulus = modulus
        self.wf = int(wf)
        self.alpha = alpha_arr
        self.beta = beta_arr
        self.gen = with_gen

    def export(self):
        num = len(self.alpha)
        exported = bytearray()
        if self.gen:
            exported +=(bytearray.fromhex('55414D30'))
        else:
            exported +=(bytes.fromhex('55414D32'))

        exported +=(mpi_en(self.modulus))
        exported += (self.wf.to_bytes(4,'big'))
        num_hex = hex(num)
        num_hex = num_hex.lstrip("0x")
        if len(num_hex) % 2 != 0:
            num_hex = "0" +num_hex
        exported +=(bytearray.fromhex(num_hex))
        for i in range(num):
            exported +=(mpi_en(self.alpha[i]))
            exported +=(mpi_en(self.beta[i]))
        return exported

    def createMaskPair(self):
        num = len(self.alpha)
        if self.gen and num == 1:

            #	We only have one pair, assumed to use a generator.
            #	We use a random exponent, sufficiently large to
            #	allow all invertible quadratic residues to be
            #	selected with almost uniform probability.

            n = self.modulus.bit_length() + 64
            bits = bytearray(secrets.token_bytes((n + 8) // 8), "utf8")
            bits[0] &= (0xFF >> ((len(bits) << 3) - n))
            e = int(bits.hex(), 16)
            v1 = pow(self.alpha[0], e, self.modulus)
            v2 = pow(self.beta[0], e, self.modulus)
        else:
            #
            # We have many pairs; we multiply together a random
            # selection of these pairs.
            #
            bits = bytearray(secrets.token_bytes((num + 7) // 8), "utf8")
            v1 = 1
            v2 = 1
            for i in range(num):
                if (bits[i // 8] & (1 << (1 & 7))) != 0:
                    v1 = (v1 * self.alpha[i]) % self.modulus
                    v2 = (v2 * self.beta[i]) % self.modulus

        return [v1, v2]

if __name__ == '__main__':
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
    md = generate(PRIV2048, 16, random_pairs)
    print(md.modulus)
    sk = makeMakwaPrivateKey(PRIV2048)
    mod = sk.modulus
    md_enc = md.export()
    print("Delegacja: ", bytes_to_str(md_enc))
    md = makeDelegation(md_enc)
    print(md.modulus)


