from random import randint


class AbstractCipher:
    """
    docstring
    """

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
    def binary_pow(a, n):
        """
        Exponentiation by squaring
        """

        if n < 0:
            return AbstractCipher.binary_pow(1 / a, -n)
        elif n == 0:
            return 1
        elif n == 1:
            return a
        elif n % 2 == 0:
            return AbstractCipher.binary_pow(a * a, n / 2)
        elif n % 2 != 0:
            return a * AbstractCipher.binary_pow(a * a, (n-1) / 2)

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
    """
    docstring
    """

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
        """
        1 < e < euler AND gcd(e, euler) == 1
        """

        e = randint(2, 25)  # mb not 25, euler
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
            binary_key_size = 2048
            decimal_key_size = 617
            warning = False
        elif rsa_type == "RSA-1536":
            binary_key_size = 1536
            decimal_key_size = 463
            warning = False
        elif rsa_type == "RSA-1024":
            binary_key_size = 1024
            decimal_key_size = 309
            warning = False
        elif rsa_type == "RSA-896":
            binary_key_size = 896
            decimal_key_size = 270
            warning = False
        elif rsa_type == "RSA-768":
            binary_key_size = 768
            decimal_key_size = 232
            warning = True
        elif rsa_type == "RSA-704":
            binary_key_size = 704
            decimal_key_size = 212
            warning = True
        elif rsa_type == "RSA-576":
            binary_key_size = 576
            decimal_key_size = 174
            warning = True

        if warning:
            warn_message = f"Warning : the key size you have chosen ({rsa_type}) can be easily cracked," \
                            f" don't use it for cryptographic issues."
        else:
            warn_message = ' '
        print(warn_message)

        p_size = int(decimal_key_size / 2)
        q_size = decimal_key_size - p_size

        p = self.get_rand_prime(10 ** (p_size - 1), 10 ** p_size - 1)
        q = self.get_rand_prime(10 ** (q_size - 1), 10 ** q_size - 1)

        return {
            'p': p,
            'q': q
        }

    def encrypt(self):
        ct = pow(self.get_plaintext(), self.get_e(), self.get_n())
        self.set_ciphertext(ct)
        return self.get_ciphertext()

    def decrypt(self):
        return pow(self.get_ciphertext(), self.get_d(), self.get_n())


# Wikipedia example
# x = RSA(111111, p=511193910726569874953935919900363873129238346355395814309112665842586420644909876720511,
        # q=494506884534583558326764414412197999730498705147369083365809132224425698427662508889603)  # e = 3
x = RSA(111111)
# print(x.get_n())
# print(x.get_euler())
# print(x.get_e())
# print(x.get_d())
# print(x.get_plaintext())
# print(x.encrypt())
# print(x.decrypt())
# print(x.get_rand_prime(25790000, 35570000))
# print(x.is_prime(31240019))
print(x.generate_key_pair("RSA-576"))
