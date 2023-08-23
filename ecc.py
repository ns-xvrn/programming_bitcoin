import hashlib, hmac


class FieldElement:
    def __init__(self, num, prime) -> None:
        if num >= prime or num < 0:
            error = f'Num {num} not in field range 0 to {prime-1}'
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f'FieldElement_{self.prime}({self.num})'
    
    def __eq__(self, __value: object) -> bool:
        if __value is None:
            return False
        return self.num == __value.num and self.prime == __value.prime
    
    def __ne__(self, __value: object) -> bool:
        return not (self == __value)
    
    def __add__(self, __value: object) -> object:
        if self.prime != __value.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + __value.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, __value: object) -> object:
        if self.prime != __value.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - __value.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __mul__(self, __value: object) -> object:
        if self.prime != __value.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * __value.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __pow__(self, exponent: int) -> object:
        n = exponent % (self.prime -1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)
    
    def __truediv__(self, __value: object) -> object:
        if self.prime != __value.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        num = (self.num * pow(__value.num, self.prime-2, self.prime)) % self.prime
        return self.__class__(num, self.prime)
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)
    

class Point:
    def __init__(self, x, y, a, b) -> None:
        self.a, self.b = a, b
        self.x, self.y = x, y
        if self.x is None and self.y is None:
            return
        if self.y ** 2 != self.x **3 + a * x + b:
            raise ValueError(f'({x}, {y}) is not on the curve')
        

    def __repr__(self) -> str:
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return f'Point({self.x.num},{self.y.num})_{self.a.num}_{self.b.num} ' \
                        + f'FieldElement({self.x.prime})'
        else:
            return f'Point({self.x},{self.y})_{self.a}_{self.b}'
        
    def __eq__(self, __value: object) -> bool:
        return self.x == __value.x and self.y == __value.y \
                and self.a == __value.a and self.b == __value.b
    
    def __ne__(self, __value: object) -> bool:
        return not (self == __value)

    def __rmul__(self, coeff) -> object:
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coeff:
            if coeff & 1:
                result += current
            current += current
            coeff >>= 1
        return result
    
    def __add__(self, __value: object) -> object:
        if self.a != __value.a or self.b != __value.b:
            raise TypeError(f'Points {self}, {__value} are not on the same curve')
        
        if (self.x == __value.x and self.y != __value.y) or \
             (self == __value and self.y == 0 * self.x):
            return self.__class__(None, None, self.a, self.b)
        
        if self.x is None:
            return __value
        
        if __value.x is None:
            return self
        
        if self.x != __value.x:
            slope = (__value.y - self.y)/(__value.x - self.x)
            x3 = (slope**2 - self.x - __value.x)
            y3 = ((slope * (self.x - x3)) - self.y)
            return self.__class__(x3, y3, self.a, self.b)
        
        if self.x == __value.x:
            slope = ((3*self.x**2) + self.a)/(2*self.y)
            x3 = (slope**2 - (2 * self.x))
            y3 = ((slope * (self.x - x3)) - self.y)
            return self.__class__(x3, y3, self.a, self.b)
        


# ------ secp265k1 curve --------

A, B = 0, 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Field(FieldElement):
    def __init__(self, num, prime=None) -> None:
        super().__init__(num, P)

    def __repr__(self):
        return f'{self.num:x}'.zfill(64)


class S256Point(Point):
    def __init__(self, x, y, a=None, b=None) -> None:
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(S256Field(x), S256Field(y), a, b)
        else:
            super().__init__(x, y, a, b)

    def __repr__(self) -> str:
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return f'S256Point({self.x}, {self.y})'
        
    def __rmul__(self, coeff) -> object:
        c = coeff % N
        return super().__rmul__(c)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r
    
    def sec(self):
        '''returns the binary version of the SEC format'''
        return b'\x04' + self.x.num.to_bytes(32, 'big') \
                + self.y.num.to_bytes(32, 'big')


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class Signature:
    def __init__(self, r, s) -> None:
        self.r, self.s = r, s

    def __repr__(self) -> str:
        return f'Signature({self.r:x}, {self.s:x})'
    

class PrivateKey:
    import hashlib
    
    def __init__(self, secret) -> None:
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return f'{self.secret:x}'.zfill(64)
    
    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)
    
    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate  
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
