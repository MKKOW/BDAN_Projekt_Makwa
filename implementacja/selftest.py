import unittest
from hashlib import sha256


from makwa import Makwa, decode

modulus = 0
privkey = 0
salt = bytes.fromhex(
    'C7' '27' '03' 'C2'
    '2A' '96' 'D9' '99'
    '2F' '3D' 'EA' '87'
    '64' '97' 'E3' '92'
)

pub2048 = bytes.fromhex(
    '55414D300100C22C40BBD056BB213AAD7C830519101AB9'
    '26AE18E3E9FC9699C806E0AE5C259414A01AC1D52E873EC'
    '08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA'
    '14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCA'
    'F96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF'
    '48984A7946F1441EA144EA4C802A457550BA3DF0F14C090'
    'A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489'
    '566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1'
    'D87477A189E73CE8E311D3D51361F8B00249FB3D8435607'
    'B14A1E70170F9AF36784110A3F2E67428FC18FB013B30FE'
    '6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3F'
    'D3CEF761')

priv2048 = bytes.fromhex(
    '55414D310080EA43D79DF0B874140A55ECD144732EAF49D9C8F0E4376F5D7297'
    '2A146679E38244F5A96EF5CE928A54251240475FD1DD968B9A77ADD16550564C'
    '1DD2424008EA83C259D53B8861C5E94F228F03C498DD3C8C6949E36602FE746D'
    '64D51489C76C74DBC2447E222ECF28FA9BD44E81410755879E71BDF8FB4A61D8'
    'AD3DF44FFC9B0080D43028EE374FEBB93B5DF8DC1C683713AB0510AF7EEBE63D'
    '33F90AF763FA2264B68B09219490A5A5644D6356859C27CDF97671122E4D9A13'
    'D91609609C469014DAE30F9AE6BC9378E79747601EEEA81846984272089C0853'
    '497FC53A51D45D37F0CB4E67D8B95921B7D293D755B49DDA55B81529A706CD67'
    'EE3BFEFEC4F3F5B3')

phc_pub2048 = bytes.fromhex(
    '55414D300100C0847EA372A4D0DBA1A32048894DC79997A10B842A9DB15FC561'
    '4BE5A573BACC72A9880A5798A387539B7A4C1C71B6B13A84DBADAF9B03F76F32'
    '708449C4FD27D2C4AFC9DC46C4A6BEC55E3A3DB1A9A256AF0539ED2AB448B853'
    'B0C1AF207B6EA294063491FB5EB2DC950E8E1E8719C4E53C06DD3E7A364B4465'
    '26817DD5373D00D671675906934DAD0F7F6CEDDA65B43368F83BAE26DAC484F0'
    '00318DBB7480225CE60EBF3A75ECA3656FC5A085F0F34ECFA9CB721BDBD8EA37'
    'B1D863422C628C73385D90654AA1D07B1A59F62342940BB48FB05B3147C94C57'
    'D790AEC749933A2A19FEC99545376E876816EB2A76AC569D08D8E1FE5181DFFB'
    '9752B5FCE1E9')

priv2048_gen = bytes.fromhex(
    '55414D710080EAC8F878EF3AA5FE24C3863D7A204C2F7011F246A14A1AEBADC8'
    '38EB9C9B112714E6042D9081807FD770469544C42C3B5BBA21A3D1D059E392AF'
    '8065C97A789EDC935E201BF0203BDD1659A7DFB68EF9CF4C7673EEC44065B7DF'
    '531EFC2A4978FF0B0B4087F9FA74ABD0C315D0ADB16C0ACBBDD0622D50EC7E36'
    'D453A2C832A30080CFE944E01DD6DA1F990D517C859D5BE2819E5A648CB4AAD1'
    '8F62B5DC75A916B021D5B032BF3BC55381C92385D33F4151EBDFAEE12873DC95'
    '2F81C0FDCB1C065A5D053C98506961E7B54FA93157C127898993315125496743'
    '4B29C8936A43FCABC7A831ADFE9D32FFB56FF6E9DA4BC5265A60D5ED3BD5176D'
    '0541D213D7AFD26B000104')


def equals(b1, b2):
    if b1 == b2:
        return True
    if (b1 is None) or (b2 is None):
        return False
    if not (len(b1) == len(b2)):
        return False
    for i in range(len(b1)):
        if not b1[i] == b2[i]:
            return False


def check(b):
    if not b:
        print("Self-test failed")

def speed_test():



def check_simple(preHash, postHashLength, workFactor):
    global salt
    mpub = Makwa(modulus, sha256, preHash, postHashLength, workFactor)
    mpriv = Makwa(privkey, preHash, postHashLength, workFactor)
    h1 = mpub.hash("test1", salt)
    check(mpub.check("test1", h1))
    check(mpriv.check("test1", h1))
    check(not mpub.check("test2", h1))
    check(not mpriv.check("test2", h1))
    h2 = mpriv.hash("test1", salt)
    check(mpub.check("test1", h2))
    check(mpriv.check("test1", h2))
    check(not mpub.check("test2", h2))
    check(not mpriv.check("test2", h2))
    check(not equals(h1, h2))


def check_delegation(priv, param_type):
    md = deleggen.generate(priv, 4096, param_type)
    sk = keygen(priv)
    mod = sk.getModulus()
    md_enc = md.export()
    md = deleggen(md_enc)
    mpub = Makwa(mod, sha256, False, 0, 4096)
    mpriv = Makwa(sk, sha256, False, 0, 4096)
    dc = mpub.hash_new_pw_delegate("test1", md)
    req = dc.get_request()
    ans = Makwa.process_del_request(req)
    h = dc.do_final_to_str(ans)
    check(mpriv.verify_pw("test1", h))

    dc = mpub.verify_pw_delegate("test1", h, md)
    req = dc.get_request()
    ans = Makwa.process_del_request(req)
    check(dc.do_final_ver(ans))


def check_wf_change():
    global salt
    m_pub_small = Makwa(modulus, sha256, False, 0, 384)
    m_priv_small = Makwa(privkey, sha256, False, 0, 384)
    m_pub_large = Makwa(modulus, sha256, False)
    m_priv_large = Makwa(privkey, sha256, False)
    hsmall = m_pub_small.hash("test1", salt)
    hlarge = m_pub_small.set_new_wf(hsmall, 4096)
    check(m_priv_large.verify_password("test1", hlarge))
    hlarge = m_priv_small.set_new_wf(hsmall, 4096)
    check(m_pub_large.verify_password("test1", hlarge))
    hsmall = m_priv_large.set_new_wf(hlarge, 384)
    check(m_pub_small.verify_password("test1", hsmall))


def check_unescrow():
    global salt
    mpub = Makwa(modulus, sha256, False, 0, 3072)
    mpriv = Makwa(privkey, sha256, False, 0, 3072)
    h = mpub.hash("test1", salt)
    check(bytearray("test1", "utf8") == mpriv.unescrow(h))


def check_phc():
    global phc_pub2048
    salt_loc = bytearray(range(4))
    input = bytearray("sample for PHC", "utf8")
    m = Makwa(phc_pub2048, 0, False)
    out = m.hash(input, salt)
    ref = b'1D4F1B0558E960CE11ADD520CA9E28F3'
    check(out == ref)


class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)

    def main(self):
        global modulus, privkey, pub2048, priv2048, priv2048_gen
        modulus = decode(pub2048)
        privkey = keygen(priv2048)
        check(modulus == privkey)
        check(privkey.exportPrivate() == priv2048)
        check(privkey.exportPublic() == pub2048)
        check(modulus == decode(pub2048))

        print("Simple API...")
        check_simple(False, 0, 384)
        check_simple(False, 12, 384)
        check_simple(True, 0, 384)
        check_simple(True, 12, 384)
        check_simple(False, 0, 4096)
        check_simple(False, 12, 4096)
        check_simple(True, 0, 4096)
        check_simple(True, 12, 4096)

        print("Work factor change...")
        check_wf_change()

        print("Unescrow...")
        check_unescrow()

        print("Delegation...")
        check_delegation(priv2048, deleggen.random_pairs)

        print("Delegation (genX)...")
        check_delegation(priv2048_gen, deleggen.generator_expand)

        print("Delegation (gen1)...")
        check_delegation(priv2048_gen, deleggen.generator_only)

        print("PHC API...")
        check_phc()

        print("Speed test...")
        speed_test()

        print("Done.")


if __name__ == '__main__':
    unittest.main()
