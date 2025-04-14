import random
import ecdsa
import time
from multiprocessing import Pool, cpu_count
import requests

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator

def send_telegram_message(message):
    """Sends a message to a Telegram bot."""
    bot_token = "6526185567:AAF9oJDCEXD0sdfIHDesNaSw_JOcvfjr0FM"
    chat_id = "7037604847"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    # requests.post(url, data={"chat_id": chat_id, "text": message})
    try:
        response = requests.post(url, data={"chat_id": chat_id, "text": message})
        response.raise_for_status()  # Will raise an exception for HTTP errors
    except requests.exceptions.RequestException as e:
        print(f"Error sending message: {e}")



def generate_public_key(priv_key):
    """Computes uncompressed public key from private key."""
    public_point = priv_key * G
    pub_x, pub_y = public_point.x(), public_point.y()
    return pub_x

def check_prefix(pub_x, pub_x_seted):
    """Check if the public x-coordinate is in the list of valid public keys."""
    pub_x_hex = hex(pub_x)[2:]  # Get the hex representation of pub_x without '0x'
    
    # Ensure the hex string is 64 characters long by padding with leading zeros
    pub_x_hex = pub_x_hex.zfill(64)
    
    print(pub_x_hex)
    
    if pub_x_hex in pub_x_seted:
        return pub_x_hex
    return None


# def generate_random_key(binary_key):
#     """Generate a new key by randomly swapping 0's and 1's while keeping their count the same."""
#     ones_count = binary_key.count('1')
#     zeros_count = len(binary_key) - ones_count

#     # Create a new list of '1's and '0's based on their counts
#     ones = ['1'] * ones_count
#     zeros = ['0'] * zeros_count

#     # Combine both lists and shuffle them
#     combined = ones + zeros
#     random.shuffle(combined)

#     # Join the shuffled bits into a string
#     return ''.join(combined)

def generate_random_key(binary_key):
    ones_count = binary_key.count('1')
    zeros_count = len(binary_key) - ones_count
    combined = ['1'] * ones_count + ['0'] * zeros_count
    random.shuffle(combined)
    return ''.join(combined)


def process_key_range(start_idx, end_idx, binary_key, pub_x_seted):
    """Generate keys for a range of indices and check if the public X in list pubs file."""
    results = []
    iteration_count = 0
    for _ in range(start_idx, end_idx):
        new_binary_key = generate_random_key(binary_key)

        priv_key = int(new_binary_key, 2)  # Convert binary to integer
        pub_x = generate_public_key(priv_key)

        # Check if the public key matches
        if check_prefix(pub_x, pub_x_seted):
            results.append((new_binary_key, hex(pub_x)))
        
        iteration_count += 1

    return results

def process_in_parallel(binary_key, pub_x_seted, num_processes=None):
    """Process key combinations in parallel."""
    # Split the work among the processes
    num_processes = num_processes or cpu_count()
    iterations_per_process = 10000 # Number of iterations per process
    total_iterations = 10000000  # Total iterations
    chunk_size = total_iterations // num_processes

    # Prepare the arguments for each process
    tasks = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_processes)]

    with Pool(processes=num_processes) as pool:
        results = pool.starmap(process_key_range, [(start, end, binary_key, pub_x_seted) for start, end in tasks])
    
    # Flatten results and print matches
    for result in results:
        for binary_key, pub_x in result:
            message = f"✅ Match Found! Binary Key: {binary_key}, Pub_X: {pub_x}"
            print(message)
            send_telegram_message(message)

def main():
    with open("pubs.txt", "r") as f:
        pub_x_seted = {line.strip()[2:66] for line in f}
        # for tests in pub_x_seted:
        #     print(tests)
    while True:
        binary_key = ''.join(random.choice(['0', '1']) for _ in range(256))
        # binary_key = "00001"

        # Start processing combinations in parallel
        process_in_parallel(binary_key, pub_x_seted)

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"Processing completed in {time.time() - start_time} seconds!")
