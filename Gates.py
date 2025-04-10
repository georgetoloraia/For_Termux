import ecdsa

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator


def generate_public_key(priv_key):
    """Computes uncompressed public key from private key."""
    public_point = priv_key * G
    pub_x, pub_y = public_point.x(), public_point.y()
    return f"04{pub_x:064x}{pub_y:064x}"  # Uncompressed format

def main():
    # Load public keys from pubs.txt into a set for fast lookup
    with open("pubs.txt", "r") as f:
        pub_keys_set = set(line.strip() for line in f)

    # Read private keys from only_x_pubs.txt
    with open("only_x_pubs.txt", "r") as f:
        private_keys = [int(line.strip(), 16) for line in f]  # Convert hex to int

    with open("minus.txt", "r") as george:
        need_test = [int(line.strip(), 16) for line in george]


    with open("found_matches.txt", "w") as output_file:
        for priv in private_keys:
            for elene in need_test:

                test_priv = (priv * elene) % N   # Multiply by M
                pub_uncompressed = generate_public_key(test_priv)

                if pub_uncompressed in pub_keys_set:
                    print(f"✅ Match Found! Private Key: {hex(test_priv)}")
                    output_file.write(f"{hex(test_priv)}\n")

if __name__ == "__main__":
    main()












    # with open("minus.txt", "a") as min:
    #     for l in private_keys:
    #         z = 55066263022277343669578718895168534326250603453777594175500187360389116729240 / l
    #         min.write(f"{str(z)}\n")