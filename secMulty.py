import ecdsa
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from random import randint
import requests
import time
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

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
        if P == Q:
            l = (3 * P.x() ** 2 + self.curve.a()) * mod_inverse(2 * P.y(), self.curve.p()) % self.curve.p()
        else:
            l = (Q.y() - P.y()) * mod_inverse(Q.x() - P.x(), self.curve.p()) % self.curve.p()

        x_r = (l ** 2 - P.x() - Q.x()) % self.curve.p()
        y_r = (l * (P.x() - x_r) - P.y()) % self.curve.p()
        return Point(self.curve, x_r, y_r)

    def scalar_mult(self, k, P):
        """Performs scalar multiplication k * P on the elliptic curve."""
        R = None  # The identity point is represented as None (point at infinity)
        Q = P
        need_test = []
        while k:
            if k & 1:  # If the least significant bit of k is 1, add Q to R
                R = self.ec_add(R, Q) if R else Q  # If R is None, we initialize it to Q
                need_test.append(R.x())  # Append the x coordinate to need_test
            Q = self.ec_add(Q, Q)  # Double the point Q
            need_test.append(Q.x())
            k >>= 1  # Right shift k by 1
        return R, need_test[-100:]

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

def process_range(start, end, ec_ops, pub_x_seted):
    """Function to process a range of private keys and check public key matches."""
    while start < end:
        priv_key = randint(start, end)  # Generate a random private key within the range
        pub_point = ec_ops.generator
        result_point, need_test = ec_ops.scalar_mult(priv_key, pub_point)

        for i in need_test:
            if isinstance(i, int):  # Ensure i is an integer
                pub_x_hex = hex(i)[2:].zfill(64)
                if pub_x_hex in pub_x_seted:  # Check if the hex value matches
                    message = f"point = {i} Priv = {priv_key}"
                    print(message)
                    send_telegram_message(message)
                    time.sleep(1)

def main():
    ec_ops = ECOperations()
    with open("pubs.txt", "r") as f:
        pub_x_seted = {line.strip()[2:66] for line in f}
    
    # Determine the number of CPU cores
    num_cores = multiprocessing.cpu_count()

    # Define the range of private keys
    start_range = 1
    end_range = N // 2


    # Divide the work into equal parts for each CPU core
    range_per_core = (end_range - start_range) // num_cores

    with ProcessPoolExecutor(max_workers=num_cores) as executor:
        for i in range(num_cores):
            start = start_range + i * range_per_core
            end = start + range_per_core if i < num_cores - 1 else end_range
            executor.submit(process_range, start, end, ec_ops, pub_x_seted)

if __name__ == "__main__":
    main()
