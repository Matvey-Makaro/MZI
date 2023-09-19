import binascii
from stb import Stb


def run_tests():
    test_convert()
    test_stb_encr()
    test_stb_decr()
    test_stb_block()
    test_stb_full_blocks()
    test_stb()

def test_convert():
    key = list(binascii.unhexlify('E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6'))
    encryptor = Stb(key)
    text = "Hello world"
    list_of_bytes = encryptor.uft8_to_list_of_bytes(text)
    new_text = encryptor.list_of_bytes_to_uft8(list_of_bytes)
    print("Text: ", text)
    print("New text:", new_text)
    assert text == new_text

def test_stb_encr():
    key = list(binascii.unhexlify('E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6'))
    encryptor = Stb(key)
    m = list(binascii.unhexlify('B194BAC80A08F53B366D008E584A5DE4'))
    c1 = binascii.hexlify(bytearray(encryptor.encrypt_block(m)))
    assert c1 == b'69cca1c93557c9e3d66bc3e0fa88fa6e'


def test_stb_decr():
    c = list(binascii.unhexlify('E12BDC1AE28257EC703FCCF095EE8DF1'))
    key = list(binascii.unhexlify('92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'))
    decryptor = Stb(key)
    d1 = binascii.hexlify(bytearray(decryptor.decrypt_block(c)))
    assert d1 == b'0dc5300600cab840b38448e5e993f421'


def test_stb_block():
    data = 'E12BDC1AE28257EC703FCCF095EE8DF1'
    key_str = '92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'
    key = list(binascii.unhexlify(key_str))
    stb = Stb(key)
    encrypted_data = stb.encrypt_block(list(binascii.unhexlify(data)))
    decrypted_data = binascii.hexlify(bytearray(stb.decrypt_block(encrypted_data)))
    assert decrypted_data == binascii.hexlify(binascii.unhexlify(data))


# def test_stb_short_text():
#     data = "Hello world!"
#     key_str = '92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'
#     key = list(binascii.unhexlify(key_str))
#     stb = Stb(key)
#
#     encrypted_data = stb.encrypt(data)
#     decrypted_data = stb.decrypt(encrypted_data)
#
#     is_failed = False
#     if type(encrypted_data) != type(str) or len(encrypted_data) == 0:
#         is_failed = True
#     if type(decrypted_data) != type(str) or len(decrypted_data) == 0:
#         is_failed = True
#
#     if is_failed or encrypted_data != decrypted_data:
#         print("test_stb() FAILED!")
#         print("data(", data, ") != encrypted_data(", encrypted_data, ")")
#     else:
#         print("test_stb() ok")

def test_stb_full_blocks():
    data = "Hello world! How are u? aaaaaaaaaaaaaaaaaaaaaaaa"
    key_str = '92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'
    key = list(binascii.unhexlify(key_str))
    stb = Stb(key)

    encrypted_data = stb.encrypt(data)
    decrypted_data = stb.decrypt(encrypted_data)

    is_failed = False
    if not isinstance(encrypted_data, str) or len(encrypted_data) == 0:
        is_failed = True
    if not isinstance(decrypted_data, str) or len(decrypted_data) == 0:
        is_failed = True

    if is_failed or data != decrypted_data:
        print("test_stb_full_blocks() FAILED!")
        print("data(", data, ") != decrypted_data(", decrypted_data, ")")
    else:
        print("test_stb_full_blocks() ok")


def test_stb():
    data = "Hello world! How are u? Hey hey hey"
    key_str = '92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'
    key = list(binascii.unhexlify(key_str))
    stb = Stb(key)

    encrypted_data = stb.encrypt(data)
    decrypted_data = stb.decrypt(encrypted_data)

    is_failed = False
    if not isinstance(encrypted_data, str) or len(encrypted_data) == 0:
        is_failed = True
    if not isinstance(decrypted_data, str) or len(decrypted_data) == 0:
        is_failed = True

    if is_failed or data != decrypted_data:
        print("test_stb() FAILED!")
        print("data(", data, ") != decrypted_data(", decrypted_data, ")")
    else:
        print("test_stb() ok")
