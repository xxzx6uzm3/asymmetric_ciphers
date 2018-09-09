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
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    @staticmethod
    def binary_pow(a, n):
        """
        Exponentiation by squaring / Алгоритм швидкого піднесення в степінь
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


class RSA(AbstractCipher):
    """
    docstring
    """

    def __init__(self, plaintext=None, ciphertext=None, p=None, q=None, e=None):
        super().__init__(plaintext, ciphertext)
        self.__p = p
        self.__q = q
        self.__e = e

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
        if self.get_e() != None:
            return self.__e
        else:
            e = randint(2, 25)  # mb not 25, euler
            while self.gcd(e, self.get_euler()) != 1:
                e = randint(2, 25)
            self.set_e(e)
            return self.get_e()

    def get_d(self):
        d = self.modular_inverse(self.get_e(), self.get_euler())
        return d

    def keys_file(self):
        public_key_file = open("public.key", "w")
        public_key_file.write("{},{}".format(self.generate_e(), self.get_n()))
        public_key_file.close()

        private_key_file = open("private.key", "w")
        private_key_file.write("{},{}".format(self.get_d(), self.get_n()))
        private_key_file.close()

        return ''

    def encrypt(self):
        # ct = self.binary_pow(self.get_plaintext(), self.get_e()) % self.get_n()

        ct = pow(self.get_plaintext(), self.get_e(), self.get_n())
        self.set_ciphertext(ct)
        return self.get_ciphertext()

    def decrypt(self):
        # дуже довго рахує
        # якщо замінити степінь на 100 000 то рахує за 5 сек...
        # decrypted_text = self.binary_pow(self.get_ciphertext(), self.get_d()) % self.get_n()

        return pow(self.get_ciphertext(), self.get_d(), self.get_n())


# Wikipedia example
# x = RSA(111111, p=3557, q=2579, e=3)
# print(x.get_n())
# print(x.get_euler())
# print(x.get_e())
# print(x.get_d())
# print(x.get_plaintext())
# print(x.encrypt())
# print(x.decrypt())