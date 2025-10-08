#!/usr/bin/env python3
"""
🔐 RSA Factorization Challenge

In 1977, Ron Rivest said that factoring a 125-digit number would take 40 quadrillion years.
Today, we can do it in seconds. Can you factor this?

RSA Parameters:
n = 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413
e = 65537
ciphertext = 911285123012386276011855754398791243

Your Mission:
1. Factor n into p and q
2. Calculate the private key d
3. Decrypt the ciphertext

Hint: This number was part of the RSA Factoring Challenge and has been factored before.
The factors are roughly equal in size.


"""

def mod_inverse(a, m):
    """Calculate modular inverse using extended Euclidean algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return (x % m + m) % m

# You need to find p and q such that p * q = n
# Then calculate:
# phi = (p-1) * (q-1)
# d = mod_inverse(e, phi)
# message = pow(ciphertext, d, n)

if __name__ == "__main__":
    print("RSA Challenge loaded successfully!")
    print("Find p and q to decrypt the message!")