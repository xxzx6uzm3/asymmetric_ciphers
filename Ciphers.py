from random import randint


class AbstractCipher:
    """ Contains a set of methods that are widely used in asymmetric ciphers """

    def __init__(self, plaintext=None, ciphertext=None):
        self.__pt = plaintext
        self.__ct = ciphertext

    def set_plaintext(self, pt):
        self.__pt = pt

    def get_plaintext(self):
        return self.__pt

    def set_ciphertext(self, ct):
        self.__ct = ct

    def get_ciphertext(self):
        return self.__ct

    @staticmethod
    def is_prime(n):
        if n > 1:
            for i in range(2, n):
                if n % i == 0:
                    return False
            return True
        else:
            return False

    @staticmethod
    def gcd(a, b):
        if a < b:
            a, b = b, a

        r = 1
        while r != 0:
            r = a % b
            if r != 0:
                a = b
                b = r

        return b

    @staticmethod
    def extended_gcd(a, b):
        """
        Find X and Y in ax + by = gcd(a,b)
        """

        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = AbstractCipher.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    @staticmethod
    def modular_inverse(a, m):
        """
        Modular Multiplicative Inverse
        """

        g, x, y = AbstractCipher.extended_gcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    @staticmethod
    def get_rand_prime(a, b):
        """
        :param a: start point
        :param b: end point
        """

        rpn = randint(a, b)

        # Fermat theorem
        while pow(2, rpn - 1, rpn) != 1 or pow(3, rpn - 1, rpn) != 1 or pow(5, rpn - 1, rpn) != 1 or \
                pow(7, rpn - 1, rpn) != 1:
            rpn = randint(a, b)
        return rpn


class RSA(AbstractCipher):
    """ The class implements encryption and decryption by the rsa method """

    def __init__(self, plaintext=None, ciphertext=None, p=None, q=None, e=None):
        super().__init__(plaintext, ciphertext)
        self.__p = p
        self.__q = q
        self.__e = e or self.generate_e()

    def set_p(self, p):
        self.__p = p

    def get_p(self):
        return self.__p

    def set_q(self, q):
        self.__q = q

    def get_q(self):
        return self.__q

    def set_e(self, e):
        self.__e = e

    def get_e(self):
        return self.__e

    def get_n(self):
        return self.get_p() * self.get_q()

    def get_euler(self):
        return (self.get_p() - 1) * (self.get_q() - 1)

    def generate_e(self):
        """ 1 < e < euler AND gcd(e, euler) == 1 """

        e = randint(2, 100)  # mb not 25, euler
        while self.gcd(e, self.get_euler()) != 1:
            e = randint(2, 25)
        self.set_e(e)
        return self.get_e()

    def get_d(self):
        d = self.modular_inverse(self.get_e(), self.get_euler())
        return d

    def generate_key_pair(self, rsa_type):
        warning = None
        if rsa_type == "RSA-2048":
            decimal_key_size = 617
            warning = False
        elif rsa_type == "RSA-1536":
            decimal_key_size = 463
            warning = False
        elif rsa_type == "RSA-1024":
            decimal_key_size = 309
            warning = False
        elif rsa_type == "RSA-896":
            decimal_key_size = 270
            warning = False
        elif rsa_type == "RSA-768":
            decimal_key_size = 232
            warning = True
        elif rsa_type == "RSA-704":
            decimal_key_size = 212
            warning = True
        elif rsa_type == "RSA-576":
            decimal_key_size = 174
            warning = True

        if warning:
            warn_message = f"Warning : the key size you have chosen ({rsa_type}) can be easily cracked," \
                            f" don't use it for cryptographic issues."
        else:
            warn_message = ' '
        print(warn_message)

        p_size = int(decimal_key_size / 2)  # 25
        q_size = decimal_key_size - p_size

        p = self.get_rand_prime(10 ** (p_size - 1), 10 ** p_size - 1)
        q = self.get_rand_prime(10 ** (q_size - 1), 10 ** q_size - 1)

        return {
            'p': p,
            'q': q
        }

    def encrypt(self):
        result = []
        pt_as_num = [ord(x) for x in list(self.get_plaintext())]
        for element in pt_as_num:
            result.append(pow(element, self.get_e(), self.get_n()))
        return result

    def show_encrypted_mess(self):
        for index, element in enumerate(self.encrypt()):
            print(f'[{index}]: {element}')
        return ''

    def decrypt(self):
        result = [chr(pow(x, self.get_d(), self.get_n())) for x in self.encrypt()]
        return result

    def show_decrypted_mess(self):
        return 'Decrypted message: ' + ''.join(self.decrypt())
