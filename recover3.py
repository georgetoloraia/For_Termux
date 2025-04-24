import ecdsa
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from random import randint
import requests
import time
import hashlib

N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

class ECOperations:
    def __init__(self):
        # Initialize SECP256k1 curve parameters
        self.curve = SECP256k1.curve
        self.generator = SECP256k1.generator
        self.order = SECP256k1.order
    
    def ec_add(self, P, Q):
        """Adds two points P and Q on the elliptic curve."""
        if P == (0, 0): return Q
        if Q == (0, 0): return P
        if isinstance(P, tuple):  # Ensure P is a Point object
            P = Point(self.curve, *P)
        if isinstance(Q, tuple):  # Ensure Q is a Point object
            Q = Point(self.curve, *Q)
        
        if P == Q:
            l = (3 * P.x() ** 2 + self.curve.a()) * mod_inverse(2 * P.y(), self.curve.p()) % self.curve.p()
        else:
            l = (Q.y() - P.y()) * mod_inverse(Q.x() - P.x(), self.curve.p()) % self.curve.p()

        x_r = (l ** 2 - P.x() - Q.x()) % self.curve.p()
        y_r = (l * (P.x() - x_r) - P.y()) % self.curve.p()
        return Point(self.curve, x_r, y_r)
    

    def scalar_mult(self, k, P, need):
        """Performs scalar multiplication k * P on the elliptic curve."""
        # Start with the identity point on the curve
        R = None  # The identity point is represented as None (point at infinity)
        Q = P
        # gio = (1579208923731619542357098500868790785283756427907490438260516314151816149433), (15792089237316195423570985008687907852837564279074904382605163141518161494335)
        step = 0
        gordo = ""
        n = 115792089237316195423570985008687907852837564279074904382605163141518161494337//2
        # print(k)
        while k:
            # print(bin(k))

            if k & 1:  # If the least significant bit of k is 1, add Q to R
                step += 1
                R = self.ec_add(R, Q) if R else Q  # If R is None, we initialize it to Q
                # print(f"step = {step} = add    {R.x()} {R.y()}")
            Q = self.ec_add(Q, Q)  # Double the point Q
            # print(f"step = {step} = Double {Q.x()}  {Q.y()}")
            k >>= 1  # Right shift k by 1
        # m = self.ec_add((104656268907628659879918005398491871252500362904110317508968003533463788905901, 66676479589663971983562588635520026174962999075133111768793445317994627594821),(51594861628377017398545351642787692069353655079274731882162068835666425266291, 100821211452479730105483456475942939513297636725414579587075212096419207932791))
        m = self.ec_add(need, R)
        # print(f"m = {step} = Double {m.x()}  {m.y()}")
        for _ in range(256):
            m = self.ec_add(Q,m)
            # print(f"m = {step} = Double {m.x()}  {m.y()}")
            if m.x() % 2 == 1:
                gordo += "1"
            else:
                gordo += "0"
        return R, gordo


def mod_inverse(a, p):
    """Computes the modular inverse of a modulo p using Extended Euclidean Algorithm."""
    t, new_t = 0, 1
    r, new_r = p, a % p
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("No modular inverse exists")
    if t < 0:
        t = t + p
    return t

def send_telegram_message(message):
    """Sends a message to a Telegram bot."""
    bot_token = "6526185567:AAF9oJDCEXD0sdfIHDesNaSw_JOcvfjr0FM"
    chat_id = "7037604847"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(url, data={"chat_id": chat_id, "text": message})
        response.raise_for_status()  # Raise an exception for HTTP errors
        if response.status_code == 200:
            print("Telegram message sent successfully")
    except requests.exceptions.RequestException as e:
        print(f"Error sending message: {e}")


def main():
    ec_ops = ECOperations()
    with open("pubs.txt", "r") as f:
        pub_x_seted = {line.strip() for line in f}

    with open("int_pubs.txt", "r") as publics:
        int_pubs = [int(line) for line in publics]

    pub_point = ec_ops.generator  # The generator point of the SECP256k1 curve
    need = (104656268907628659879918005398491871252500362904110317508968003533463788905901,66676479589663971983562588635520026174962999075133111768793445317994627594821)
    priv_key = 0b01101100101010101010101011010100101010101010101010010101101010010101010111101010100010110100101010010010001010101001011011010100011011010110101011010101001001010101010101010100101010000001010001011010100010101010101010010001010101010101101010100101101010110001011101101001101010110101011010
    while True:
        result_point, z = ec_ops.scalar_mult(priv_key, pub_point, need)
        neee = f"04{hex(result_point.x())[2:].zfill(64)}{hex(result_point.y())[2:].zfill(64)}"
        # print(neee)

            # # print(result_point.x(), result_point.y())
        # z_int = int(z, 2)
        # print(z)
        # print(hex(z_int))
        # print(len(z))
        # print("- - " * 25)
        # print("| | | " * 30)
        # result_point_1, l= ec_ops.scalar_mult(z_int, pub_point, need)
        # print(result_point_1)
        # puu = f"04{hex(result_point_1.x())[2:].zfill(64)}{hex(result_point_1.y())[2:].zfill(64)}"
        # print(puu)

        # public_key = neee

        # Convert the public key from hex to bytes
        public_key_bytes = bytes.fromhex(neee)

        # SHA-256
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        # print(sha256_hash)
        # Convert sha256_hash to a binary string
        binary_string = ''.join(format(byte, '08b') for byte in sha256_hash)

        puu = result_point.x()
        # print(puu)
        if puu in int_pubs:
            message = priv_key
            print(message)
            send_telegram_message(message)
            break
        
        priv_key = int(binary_string, 2)

    # result_point_2 = ec_ops.scalar_mult(z_int, pub_point)
    # print(result_point_2)
    # pee = f"04{hex(result_point_2.x())[2:].zfill(64)}{hex(result_point_2.y())[2:].zfill(64)}"
    # print(pee)
    # if puu in pub_x_seted:
        # print(puu)
        # print(z_int)
        # re, l = ec_ops.scalar_mult(z_int, pub_point)
        # if re.x() in int_pubs:
        #     print(z_int)

        # priv_key += 6511354865465465465
        # if priv_key % 1000 == 0:

# print("= = = " * 30)
# print(f"1 = {N-1 - 104377289330232701024746237183601627587377292859143290110082341981773663091773}")
# print(f"2 = {N//2 - 104377289330232701024746237183601627587377292859143290110082341981773663091773}")
# print(f"3 = {104377289330232701024746237183601627587377292859143290110082341981773663091773 - N//2}")


if __name__ == "__main__":
    main()


"""
1110011011000011011100111100001111000001111111101111101101011011001101011010100111010010001001001110110011110010100010000000111000011010111111101000111100111011011010010111011010100101010001011110100001110000101110001110000001111011101000001011110000111101
104377289330232701024746237183601627587377292859143290110082341981773663091773
"""

'''
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4025e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4125e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4225e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4325e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4425e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4525e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4625e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4725e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4825e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4925e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4a25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4b25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4c25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4d25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4e25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4f25e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad

'''


''''
4ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4025e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56a
04d74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea4025e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56a

04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea425e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
04ad74ec472794bb546214bd8613bb247e6cb95b0a7903b653d488f55eeda4aea425e289bc6db341ac22672ebbd394674869d97bcf581c96d845b3a3400cf56ad
'''