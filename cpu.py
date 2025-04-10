import ecdsa
import multiprocessing

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator


def generate_public_key(priv_key):
    """Computes uncompressed public key from private key."""
    public_point = priv_key * G
    pub_x, pub_y = public_point.x(), public_point.y()
    return f"04{pub_x:064x}{pub_y:064x}"  # Uncompressed format


def process_chunk(private_keys_chunk, pub_keys_set, need_test, output_file):
    """Processes a chunk of private keys in parallel."""
    results = []
    for priv in private_keys_chunk:
        # print(priv)
        for elene in need_test:
            test_priv = (priv + elene) % N
            pub_uncompressed = generate_public_key(test_priv)

            if pub_uncompressed in pub_keys_set:
                results.append(hex(test_priv))
                print(f"es aris private ioo = {test_priv}")

    # Save found results to file
    if results:
        with open(output_file, "a") as f:
            for key in results:
                f.write(f"{key}\n")
                print(f"✅ Match Found! Private Key: {key}")


def main():
    # Load public keys from pubs.txt into a set for fast lookup
    with open("pubs.txt", "r") as f:
        pub_keys_set = set(line.strip() for line in f)

    # Read private keys from only_x_pubs.txt
    with open("only_x_pubs.txt", "r") as f:
        private_keys = [int(line.strip(), 16) for line in f]  # Convert hex to int

    # Read numbers from minus.txt
    with open("minus.txt", "r") as george:
        need_test = [int(line.strip(), 16) for line in george]

    output_file = "found_matches.txt"
    num_cores = multiprocessing.cpu_count()  # Get the number of CPU cores
    chunk_size = len(private_keys) // num_cores  # Split private keys for each core

    # Split private keys into chunks for multiprocessing
    private_key_chunks = [
        private_keys[i : i + chunk_size] for i in range(0, len(private_keys), chunk_size)
    ]

    # Create and start parallel processes
    processes = []
    for chunk in private_key_chunks:
        p = multiprocessing.Process(target=process_chunk, args=(chunk, pub_keys_set, need_test, output_file))
        processes.append(p)
        p.start()

    # Wait for all processes to finish
    for p in processes:
        p.join()

    print("✅ Processing completed!")


if __name__ == "__main__":
    main()
