import ecdsa
import multiprocessing
import random

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator

def generate_public_key(priv_key):
    """Computes uncompressed public key from private key."""
    public_point = priv_key * G
    pub_x, pub_y = public_point.x(), public_point.y()
    return pub_x, pub_y  # Return only X, Y for comparison

def process_chunk(chunk_size, pub_x_set, need_test, output_file):
    """Processes randomly generated private keys in parallel."""
    results = []

    for _ in range(chunk_size):
        random_priv = random.randrange(1, N)

        for elene in need_test:
            test_priv_add = (random_priv + elene) % N
            test_priv_mul = (random_priv * elene) % N

            pub_x_add, _ = generate_public_key(test_priv_add)
            pub_x_mul, _ = generate_public_key(test_priv_mul)

            # Check if X matches any in the set of public X values
            if pub_x_add in pub_x_set:
                results.append(("+", hex(test_priv_add)))
                print(f"✅ Match Found (ADD)! Private Key: {hex(test_priv_add)}")

            if pub_x_mul in pub_x_set:
                results.append(("*", hex(test_priv_mul)))
                print(f"✅ Match Found (MUL)! Private Key: {hex(test_priv_mul)}")

    if results:
        with open(output_file, "a") as f:
            for mode, key in results:
                f.write(f"{mode}: {key}\n")

def main():
    # Load only X coordinates from pubs.txt into a set for fast lookup
    with open("pubs.txt", "r") as f:
        pub_x_set = {line.strip()[2:66] for line in f}  # Extract only the X part of the public keys

    # Read numbers from minus.txt
    with open("minus.txt", "r") as f:
        need_test = [int(line.strip(), 16) for line in f]

    output_file = "found_matches.txt"
    num_cores = multiprocessing.cpu_count()

    processes = []
    chunk_size = 1000000000  # Each core will test 1000 random keys

    for _ in range(num_cores):
        p = multiprocessing.Process(
            target=process_chunk, args=(chunk_size, pub_x_set, need_test, output_file)
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    print("✅ Processing completed!")

if __name__ == "__main__":
    main()
