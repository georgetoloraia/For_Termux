import ecdsa
from random import randint

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator

def generate_public_key(priv_key):
    """Computes uncompressed public key from private key."""
    public_point = priv_key * G
    pub_x, pub_y = public_point.x(), public_point.y()
    return pub_x

with open("int_pubs.txt", "r") as s:
        int_pubs = {int(line) for line in s}

# with open("pubs.txt", "r") as f:
#         int_pubs = {int(line, 16) for line in f}

# Example private key
priv_key = 0b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000  # Example binary private key

# Generate public key from the original private key
# pub_x_original = generate_public_key(priv_key)

# Concatenate the private key with itself
# priv_key_concat = 0b10000101110011101100011011010010111010110010101110100010111000100110000111100000101011111110000001001011001100101010000010001100010111111010110010111001010010101101100100001000111010110011100010111111100101001100110110001011001001110001110101111101000010111010110100001101011111011100000010100100011100010100110010001110110110001001101000001011000111110100100000101011101000101110100110111001011100110101111010010010110101101000011011101011011101010100100111001111011101000101111000100101110011110010110110110101111  # Concatenate by doubling the value
# pub_x_concat = generate_public_key(priv_key_concat)

# Print original and concatenated public key X values
# print(f"Original Public X: {hex(pub_x_original)}")
# print(f"Concatenated Public X: {hex(pub_x_concat)}")

# pub_x_2 = generate_public_key(priv_key_concat)

# Check if the concatenated public key X is 2 times the original public key X
# if pub_x_concat == (2 * pub_x_original) % N:
#     print("✅ Concatenated public key is 2 times the original public key.")
# else:
#     print("❌ Concatenated public key does not match the expected result.")
# for _ in range(100000):
# for res in int_pubs:
#     # res = randint(2**256, 2**257)
#     # print(res)
#     while res > 0:
#         test = res % N
#         # print(test)
#         double = generate_public_key(test)
#         # print(f"Original Doubled X: {hex(double)}")
#         if double in int_pubs:
#             print(f"✅ pub_x_original == (2 * test) & N = {double} from {test}")
#         res >>= 1
#         # print(res)


# res = randint(2**256, 2**257)
# print(res)
while priv_key > 0:
    test = priv_key
    # test = res % N
    # print(test)
    while test > 0:
        double = generate_public_key(test)
        # print(f"Original Doubled X: {hex(double)}")
        if double in int_pubs:
            message = f"✅ pub_x_original == (2 * test) & N = {double} from {priv_key}"
            print(message)
            with open("FOUND.txt", "a") as j:
                 j.wriet(message)
        test >>= 1
    priv_key += randint(1, 2**256)
    # print(priv_key)