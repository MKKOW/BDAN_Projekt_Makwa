from encoding import mpi_en, mpi_de
from makwa import Makwa
from makwakeys import makeMakwaPrivateKey, makeRandNonZero, getMagic
from binascii import hexlify
from modInverse import modInverse
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
        if num < 80 and (num != 1 or not with_gen):
            raise ValueError("Too few mask pairs")
        alpha = [0] * num
        beta = [0] * num
        for i in range(num):
            alpha_len = int(hexlify(encoded[readlen:readlen + 2]), 16)
            readlen += 2
            alpha[i] = int(hexlify(encoded[readlen: readlen +alpha_len]), 16)
            readlen += alpha_len
            beta_len = int(hexlify(encoded[readlen:readlen +2]), 16)
            readlen += 2
            beta[i] = int(hexlify(encoded[readlen: readlen + beta_len]), 16)
            readlen += beta_len
        if readlen < len(encoded):
            raise ValueError('Trailing garbage')
        deleggen(modulus, wf, alpha, beta, with_gen)
    else:
        raise ValueError("unknown Makwa delegation parameter type")



def generate(mparam, wf, param_type=random_pairs):
    mkw = Makwa(makeMakwaPrivateKey(mparam).p*makeMakwaPrivateKey(mparam).q, None, False, 0, 0)
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
    beta[0] = modInverse(pow(alpha[0], pow(2, wf)), mod)
    for i in range(1, num, 1):
        alpha[i] = (pow(alpha[i - 1], 2, mod))
        beta[i] = (pow(beta[i - 1], 2, mod))
    return deleggen(mod, wf, alpha, beta, True)


def generate_rnd_pairs(mkw, wf):
    mod = mkw.n
    num = 300
    alpha = [0] * num
    beta = [0] * num
    for i in range(num):
        r = makeRandNonZero(mod)
        alpha[i] = (r * r % mod)
        beta[i] = modInverse(pow(alpha[i], pow(2, wf)), mod)
    return deleggen(mod, wf, alpha, beta, False)

class deleggen:
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
        self.wf = wf
        self.alpha = alpha_arr
        self.beta = beta_arr
        self.gen = with_gen

    def export(self):
        num = len(self.alpha)
        if self.gen:
            magic = int('55414D40', 16)
        else:
            magic = int('55414D32', 16)
        exported = bytearray()
        exported.append(magic)
        exported.append(mpi_en(self.modulus))
        exported.append(self.wf)
        exported.append(num)
        for i in range(num):
            exported.append(mpi_en(self.alpha[i]))
            exported.append(mpi_en(self.beta[i]))
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



