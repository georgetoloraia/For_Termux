from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
from random import SystemRandom
from multiprocessing import Pool, cpu_count
import os

# --- CONFIG ---
MODE = "random"  # "random" or "structured"
NUM_K = 12  # How many k values to generate/test
STRUCTURED_START = 2**128
STRUCTURED_STEP = 1
PUBS_FILE = "allpubs.txt"
MATCH_LOG = "matches_found.txt"
MAX_STEPS = 10000

# --- EC Setup ---
curve = SECP256k1.curve
G = SECP256k1.generator
order = G.order()
gx = G.x()

# --- Load known x values ---
def load_allpubs_x(path):
    x_set = set()
    with open(path, 'r') as f:
        for line in f:
            if ',' in line:
                x_str, _ = line.strip().split(',')
                try:
                    x = int(x_str)
                    x_set.add(x)
                except ValueError:
                    continue
    return x_set

known_x = load_allpubs_x(PUBS_FILE)

# --- NAND logic ---
def nand_256(a, b):
    return (~(a & b)) & ((1 << 256) - 1)

# --- Worker function ---
def process_k(start_k):
    visited = set()
    k = start_k

    for step in range(MAX_STEPS):
        Q = k * G
        qx = Q.x()
        new_k = nand_256(qx, gx)
        R = new_k * G
        rx = R.x()

        if rx in known_x:
            match_line = f"[MATCH] start_k={start_k} step={step}\n  k={k}\n  new_k={new_k}\n  R.x={rx}"
            print(match_line)
            with open(MATCH_LOG, 'a') as f:
                f.write(match_line + '\n')
            return

        if new_k == 0 or new_k == k or new_k in visited:
            return

        visited.add(k)
        k = new_k

# --- Generate k values ---
def generate_k_values(mode="random", num=100, start=2**128, step=1):
    if mode == "random":
        rand = SystemRandom()
        return [rand.randint(1, order - 1) for _ in range(num)]
    elif mode == "structured":
        return [start + i * step for i in range(num)]
    else:
        raise ValueError("Invalid mode: use 'random' or 'structured'")

# --- Main execution ---
if __name__ == "__main__":
    if os.path.exists(MATCH_LOG):
        os.remove(MATCH_LOG)

    print(f"[+] Generating {NUM_K} '{MODE}' k values...")
    start_k_list = generate_k_values(MODE, NUM_K, STRUCTURED_START, STRUCTURED_STEP)

    print(f"[+] Loaded {len(known_x)} known x-coordinates.")
    print(f"[+] Running parallel check with {min(cpu_count(), len(start_k_list))} CPUs...")

    with Pool(processes=min(cpu_count(), len(start_k_list))) as pool:
        pool.map(process_k, start_k_list)
