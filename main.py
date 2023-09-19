import binascii
from tests import run_tests
from stb import Stb


def encrypt_file(file_name, encrypted_file_name, key):
    with open(file_name, "r") as read_file:
        text = read_file.read()

    with open(encrypted_file_name, 'w') as write_file:
        stb = Stb(key)
        try:
            encrypted_data = stb.encrypt(text)
        except RuntimeError as ex:
            print(ex)
            return
        write_file.write(encrypted_data)


def decrypt_file(encrypted_file_name, decrypted_file_name, key):
    with open(encrypted_file_name, "r") as read_file:
        text = read_file.read()

    with open(decrypted_file_name, "w") as write_file:
        stb = Stb(key)
        try:
            decrypted_data = stb.decrypt(text)
        except RuntimeError as ex:
            print(ex)
            return
        write_file.write(decrypted_data)


def main() -> None:
    run_tests()

    file_name = "Text.txt"
    encrypt_file_name = file_name + "_encrypt"
    decrypt_file_name = file_name + "_decrypt"
    key_str = '92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511'
    key = list(binascii.unhexlify(key_str))
    encrypt_file(file_name, encrypt_file_name, key)
    decrypt_file(encrypt_file_name, decrypt_file_name, key)


if __name__ == '__main__':
    main()
