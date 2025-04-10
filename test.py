import ecdsa

# SECP256K1-ის პარამეტრები
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator

def generate_public_key(priv_key):
    """Computes public key (X, Y) from private key."""
    pub_point = priv_key * G
    return pub_point.x(), pub_point.y()

# ორი ცვლადი private key
priv1 = 3
priv2 = 5

# Public Keys
pub1 = priv1 * G
pub2 = priv2 * G

# Elliptic Curve Point Addition
pub3 = pub1 + pub2

print(f"Priv1={priv1}, Pub1_X={hex(pub1.x())}")
print(f"Priv2={priv2}, Pub2_X={hex(pub2.x())}")
print(f"Priv1 + Priv2, Pub3_X={hex(pub3.x())}")

# შემოწმება -> Pub3 == (Priv1 + Priv2) * G ?
expected_pub3 = (priv1 + priv2) * G
print(f"Does Pub1 + Pub2 == Pub3? {pub3 == expected_pub3}")
