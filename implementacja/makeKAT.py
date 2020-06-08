from hashlib import sha256, sha512

from makwakeys import decodePublic, makeMakwaPrivateKey
from makwa import Makwa
from selftest import check, equals
from encoding import bytes_to_str, encode

h = sha256()
pub2048 = bytes.fromhex(
    '55414D300100C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C8'
    '06E0AE5C259414A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F7'
    '1A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2'
    'CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA'
    '4C802A457550BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D2'
    '7865A489566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A18'
    '9E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F'
    '2E67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0'
    'FE3FD3CEF761'
)
priv2048 = bytes.fromhex(
    '55414D310080EA43D79DF0B874140A55ECD144732EAF49D9C8F0E4376F5D7297'
    '2A146679E38244F5A96EF5CE928A54251240475FD1DD968B9A77ADD16550564C'
    '1DD2424008EA83C259D53B8861C5E94F228F03C498DD3C8C6949E36602FE746D'
    '64D51489C76C74DBC2447E222ECF28FA9BD44E81410755879E71BDF8FB4A61D8'
    'AD3DF44FFC9B0080D43028EE374FEBB93B5DF8DC1C683713AB0510AF7EEBE63D'
    '33F90AF763FA2264B68B09219490A5A5644D6356859C27CDF97671122E4D9A13'
    'D91609609C469014DAE30F9AE6BC9378E79747601EEEA81846984272089C0853'
    '497FC53A51D45D37F0CB4E67D8B95921B7D293D755B49DDA55B81529A706CD67'
    'EE3BFEFEC4F3F5B3'
)
salts = [bytearray.fromhex('b82cb42e3a2dfc2ad60b8b76c666b015'),
         bytearray.fromhex('079609036dd1894ce37d08ab2021a302'),
         bytearray.fromhex('1adbc1e6a9dd481fff00eb93b28e9ace'),
         bytearray.fromhex('d88f1d9b71d0a159f11b288478182916'),
         bytearray.fromhex('1c3722644219b5cd55f368cfcbe54ed7'),
         bytearray.fromhex('82ef588dd5c552dfa2f646998791a575'),
         bytearray.fromhex('4b9f85742f0cfbdade12b73e54b99510'),
         bytearray.fromhex('afa6a092f2354a8aaa0e802356e47e01'),
         bytearray.fromhex('60f48cdc693f2b7bc06bc913538630bc'),
         bytearray.fromhex('06befd62eac8e05d4d6539a4e9f5bafa'),
         bytearray.fromhex('739c4051f7046c33ad111e7fed3c9d34'),
         bytearray.fromhex('312444b683889e945ed4472649e16a0d'),
         bytearray.fromhex('bffebb985bc4c75f77a781d30fe87aee'),
         bytearray.fromhex('63f9c227d25cae3bd9454f61050a90bd'),
         bytearray.fromhex('e238172514cab357b150ec32726e70ac')]
wf_small = 384
wf_large = 4096


def printKDF(banner, hashFunction, input, outlen):
    global h
    output = bytearray(outlen)
    Makwa.kdf(Makwa(123,hashFunction), input, output)
    print(banner)
    print("input", input)
    print("output", output)
    print('\n')
    h.update(output)


def printKAT(banner, mpub, mpriv):
    input = bytearray(150)
    for i in range(len(input)):
        input[i] = 17 + 73 * i

    printKAT(banner, mpub, mpriv, input)
    input = bytearray(13)
    for j in range(22):
        for k in range(13):
            input[k] = 13 * j + k + 8
        printKAT(banner, mpub, mpriv, input)


def printKAT(banner, mpub, mpriv, input):
    for salt_num in salts:
        salt = bytearray(salts[salt_num])
        printKAT(banner, mpub, mpriv, input, salt, 10 + salt_num)


def printKAT(banner, mpub, mpriv, input, salt, ph_len):
    printKAT(banner, mpub, mpriv, input, salt, False, 0)
    printKAT(banner, mpub, mpriv, input, salt, False, ph_len)
    printKAT(banner, mpub, mpriv, input, salt, True, 0)
    printKAT(banner, mpub, mpriv, input, salt, True, ph_len)


def printKAT(banner, mpub, mpriv, input, salt, pre_hash, post_hash_len):
    global wf_small, wf_large, h
    h1 = Makwa(mpub.n, mpub.h, pre_hash, post_hash_len, wf_small).hash(input, salt)
    h2 = Makwa(mpriv.n, mpriv.h, post_hash_len, wf_small).hash(input, salt)
    check(equals(h1, h2))
    out_sm_str = bytes_to_str(h2)
    h3 = Makwa(mpub.n, mpub.h, pre_hash, post_hash_len, wf_large).hash(input, salt)
    h4 = Makwa(mpriv.n, mpriv.h, post_hash_len, wf_large).hash(input, salt)
    check(equals(h3, h4))
    out_lg_str = bytes_to_str(h4)
    print(banner)
    print("input", input)
    print("salt", salt)
    print("pre-hashing: ", pre_hash)
    if post_hash_len == 0:
        print("post-hashing: false")
    else:
        print("post-hashing: ", post_hash_len)
    print("bin", wf_small, h1)
    print("bin", wf_large, h2)
    print("str", wf_small, ": ", out_sm_str)
    print("str", wf_large, ": ", out_lg_str)
    print('\n')
    h.update(h1)
    h.update(h2)
    h.update(bytes(out_sm_str, "utf8"))
    h.update(bytes(out_lg_str, "utf8"))
    if (not pre_hash) and post_hash_len == 0:
        upi_1 = mpriv.unescrow(h1, salt, wf_small)
        check(equals(upi_1, input))
        upi_2 = mpriv.unescrow(h3, salt, wf_large)
        check(equals(upi_2, input))


def println(name, value):
    print(name, ": ")
    for i in range (len(value)):
        print("%02x", value[i] & 0xFF)
    print('\n')




class makeKAT:

    def __init__(self):
        self.process()

    def process(self):
        global h
        mod = decodePublic(pub2048)
        pkey = makeMakwaPrivateKey(priv2048)
        check(pkey.modulus == mod)
        mpub = Makwa(mod, sha256, False, 0, 1024)
        mpriv = Makwa(pkey, sha256, False, 0, 1024)

        for i in range(200):
            input = bytearray(i)
            for j in range(i):
                input[j] = 7 * i + 83 * j
            printKDF("KDF/SHA-256", sha256, input, 100)
            printKDF("KDF/SHA-512", sha512, input, 100)

        pwd = "Gego beshwaji'aaken awe makwa; onzaam naniizaanizi."
        pi = bytes(pwd, "utf8")
        salt = bytearray.fromhex('C72703C22A96D9992F3DEA876497E392')
        ref = bytearray.fromhex('C9CEA0E6EF09393AB1710A08')
        mpub_to_hash = Makwa(mpub, sha256, True, 12, 4096)
        check(equals(ref, mpub_to_hash.hash(pi, salt)))
        detailed = mpub.encode_output(salt, False, 12, 4096, ref)
        print("2048-bit modulus, SHA-256")
        print("input ", pi)
        print("salt ", salt)
        print("pre-hashing: false")
        print("post-hashing: 12")
        print("bin4096 ", ref)
        print("str4096: ", detailed)
        print()
        h.update(ref)
        h.update(bytes(detailed, "utf8"))

        printKAT("2048-bit modulus, SHA-256", mpub, mpriv)
        mpub = Makwa(mod, sha512, False, 0, 1024)
        mpriv = Makwa(pkey, sha512, False, 0, 1024)
        printKAT("2048-bit modulus, SHA-512", mpub, mpriv)

        print("KAT digest", h.digest())


