import binascii
from stb import Stb


def run_tests():
    test_stb_encr()
    test_stb_decr()


def test_stb_encr():
    key = list(binascii.unhexlify('E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6'))
    encryptor = Stb(key)
    m = list(binascii.unhexlify('B194BAC80A08F53B366D008E584A5DE4'))
    c1 = binascii.hexlify(bytearray(encryptor.encrypt_block(m)))
    assert c1 == b'69cca1c93557c9e3d66bc3e0fa88fa6e'


def test_stb_decr():
    c = list(binascii.unhexlify('E12BDC1AE28257EC703FCCF095EE8DF1'))
    key2 = list(binascii.unhexlify('92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'))
    decryptor = Stb(key2)
    d1 = binascii.hexlify(bytearray(decryptor.decrypt_block(c)))
    assert d1 == b'0dc5300600cab840b38448e5e993f421'
