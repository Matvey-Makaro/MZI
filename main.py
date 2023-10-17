import Crypto.Util.number
import Crypto.Random


class Rabin:
    __bits = 0
    __public_key = 0
    __private_key = 0
    __message = ""

    def __init__(self, bits):
        self.__bits = bits

    def get_public_key(self):
        return self.__public_key

    def set_public_key(self, k):
        self.__public_key = k

    def get_private_key(self):
        return self.__private_key

    def set_private_key(self, k):
        self.__private_key = k

    def __generate_prime_number(self):
        while True:
            prime_number = Crypto.Util.number.getPrime(self.__bits)
            if (prime_number % 4) == 3:
                break
        return prime_number

    def __convert_message(self, message):
        converted = self.__convert_by_type(message)
        bit_string = bin(converted)
        output = bit_string + bit_string[-6:]
        int_output = int(output, 2)
        return int_output

    def __extended_euclidean(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, y, x = self.__extended_euclidean(b % a, a)
            return gcd, x - (b // a) * y, y

    @staticmethod
    def __convert_by_type(message):
        if isinstance(message, str):
            message = Crypto.Util.number.bytes_to_long(message.encode('utf-8'))
        else:
            message = message
        return message

    @staticmethod
    def __select_solution(solutions):
        for i in solutions:
            binary = bin(i)
            append = binary[-6:]
            binary = binary[:-6]

            if append == binary[-6:]:
                return i
        return

    def generate_keys(self):
        p = self.__generate_prime_number()
        q = self.__generate_prime_number()
        if p == q:
            print(p, q, "Numbers cannot be same! Generating again...")
            return self.generate_keys()
        n = p * q
        self.set_public_key(n)
        self.set_private_key((p, q))

    def encrypt(self, message):
        self.__message = message
        message = self.__convert_message(message)
        return pow(message, 2, self.get_public_key())

    def decrypt(self, cipher):
        n = self.get_public_key()
        p = self.get_private_key()[0]
        q = self.get_private_key()[1]

        ext = self.__extended_euclidean(p, q)
        a = ext[1]
        b = ext[2]

        r = pow(cipher, (p + 1) // 4, p)
        s = pow(cipher, (q + 1) // 4, q)

        x = ((a * p * s + b * q * r) % n)
        y = ((a * p * s - b * q * r) % n)

        solutions = [x, n - x, y, n - y]

        plain_text = self.__select_solution(solutions)

        string = bin(plain_text)
        string = string[:-6]
        plain_text = int(string, 2)

        decrypted_text = self.__get_decrypted_text(plain_text)

        return decrypted_text

    def __get_decrypted_text(self, plain_text):
        if isinstance(self.__message, str):
            formatted_text = format(plain_text, 'x')
            text_decrypted = bytes.fromhex(formatted_text).decode()
        else:
            text_decrypted = plain_text
        return text_decrypted

    def encrypt_file(self, input_file, output_file):
        with open(input_file, "r") as file:
            text = file.read()

        cipher_text_string = self.encrypt(text)

        with open(output_file, "w") as file:
            file.write(str(cipher_text_string))

    def decrypt_file(self, input_file, output_file):
        with open(input_file, "r") as file:
            cipher_text_string = file.read()

        decrypted_text_string = self.decrypt(int(cipher_text_string))
        with open(output_file, "w") as file:
            file.write(str(decrypted_text_string))


if __name__ == '__main__':
    input_filename = 'test.txt'
    output_filename = 'encrypted.txt'
    decrypted_filename = 'decrypted.txt'

    rabin = Rabin(512)
    rabin.generate_keys()

    rabin.encrypt_file(input_filename, output_filename)
    rabin.decrypt_file(output_filename, decrypted_filename)
