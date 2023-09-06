from lib import *


def GOST_28147_89_ECB(text, keys, mode):
    text = [feistel_cipher(i, keys, mode) for i in text]
    crypted_text = join_64bits(text)
    return crypted_text


def GOST_28147_89_GUM(text, key, keys, mode):
    result = []

    iv = 0x71EF0B1F3BE0394F
    iv = GOST_28147_89(iv, key, "e")

    C1 = 0x1010101
    C2 = 0x1010104

    N4 = iv >> 32 & 0xFFFFFFFF
    N3 = iv & 0xFFFFFFFF
    for t in text:
        N4 = (N4 + C2) & 0xFFFFFFFF
        N3 = ((N3 + C1 - 1) % 0xFFFFFFFF) + 1

        N1 = N3
        N2 = N4

        N = (N2 << 32) | N1
        gamma = GOST_28147_89(N, key, "e")
        result.append(t ^ gamma)
    return join_64bits(result)


def GOST_28147_89(text, key, mode="e", op_mode="ECB", ):
    temp = 0
    if len(hex(text)[2:]) % 16 > 0:
        temp = 1
    text = [(text >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(len(hex(text)) // 16 + temp)]
    if temp == 1:
        text[len(text) - 1] = text[len(text) - 1] << (64 - len(hex(text[len(text) - 1]) * 4))
    keys = gen_key(key)

    if op_mode == "ECB":
        crypted_text = GOST_28147_89_ECB(text, keys, mode)
        return crypted_text
    if op_mode == "GUM":
        crypted_text = GOST_28147_89_GUM(text, key, keys, mode)
        return crypted_text


def encrypt_file(file_name, encrypted_file_name, key):
    with open(file_name, "r") as read_file:
        lines = read_file.readlines()

    with open(encrypted_file_name, 'w') as write_file:
        for line in lines:
            line_to_encrypt = int(utf8ToHex(line), 16)
            crypted_line = str(GOST_28147_89(line_to_encrypt, key, "e", "GUM"))
            write_file.write(crypted_line +'\n')


def decrypt_file(encrypted_file_name, decrypted_file_name, key):
    with open(encrypted_file_name, "r") as read_file:
        lines = read_file.readlines()

    with open(decrypted_file_name, "w") as write_file:
        for line in lines:
            line_to_decrypt = int(line.removesuffix('\n'))
            decrypted_line = hexToUtf8(intToHex(GOST_28147_89(line_to_decrypt, key,"d", "GUM")))
            write_file.write(decrypted_line)


def main():
    fileName = "Text.txt"
    encryptFileName = fileName + "_encrypt"
    decryptFileName = fileName + "_decrypt"
    key = 0x287fc759c1ad6b59ac8597159602217e9a03381dcd943c4719dcca000fb2b577
    encrypt_file(fileName, encryptFileName, key)
    decrypt_file(encryptFileName, decryptFileName, key)

    # textStr = utf8ToHex(file_read('EnText.txt'))
    # text = int(textStr, 16)
    # key = 0x287fc759c1ad6b59ac8597159602217e9a03381dcd943c4719dcca000fb2b577
    #
    # # mode = input("Введите режим работы {ECB, CBC, CFB, OFB}: ")
    # mode = "GUM"
    # print(f"Режим работы {mode}")
    #
    # crypted_text = GOST_28147_89(text, key, "e", mode)
    # encrypted_text = GOST_28147_89(crypted_text, key, "d", mode)
    #
    # # crypted_text = intToHex(crypted_text)
    # encrypted_text = hexToUtf8(intToHex(encrypted_text))
    #
    # print(f"Исходный текст {file_read('EnText.txt')}")
    # print(f"Исходный текст в числовом обозначении {text}")
    #
    # print(f"\nКлюч {key}")
    #
    # # print(f"\nЗашифрованный текст {hexToUtf8(crypted_text)}")
    # # print(f"Зашифрованный текст в числовом обозначении {crypted_text}")
    #
    # print(f"\nДешифрованный текст {encrypted_text}")
    # # print(f"Дешифрованный текст в числовом обозначении {encrypted_text}")
    #
    # # file_write('DecText.txt', hexToUtf8(crypted_text))


if __name__ == '__main__':
    main()
