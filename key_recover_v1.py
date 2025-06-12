import os
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey
from multiprocessing import Pool, cpu_count
import binascii
from sympy import primefactors

# SECP256k1 curve parameters
curve = Curve.get_curve('secp256k1')
n = int(curve.order)  # Curve order
G = curve.generator  # Base point

# Read public keys from allpubs.txt (x,y in decimal)
def read_public_keys(filename):
    public_keys = []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if ',' in line:
                x_dec, y_dec = map(int, line.split(','))
                x_hex = hex(x_dec)[2:].zfill(64).lower()
                y_hex = hex(y_dec)[2:].zfill(64).lower()
                public_keys.append((x_hex, y_hex))
    return public_keys

# Read x-coordinates from only_x.txt
def read_only_x(filename):
    x_coords = set()
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip().lower()
            if len(line) in (63, 64) and all(c in '0123456789abcdef' for c in line):
                if len(line) == 63:
                    line = '0' + line
                x_coords.add(line)
    return x_coords

# Prime factorization key derivation
def prime_factor_derivation(args):
    x_hex, y_hex, x_coords = args
    x_int = int(x_hex, 16)
    y_int = int(y_hex, 16)
    
    # Compute sum of x and y
    sum_xy = (x_int + y_int) % n
    
    # Get prime factors (limit to first 3 for efficiency)
    factors = primefactors(sum_xy)[:3]
    if not factors:
        return False
    
    # Combine prime factors (product modulo n)
    base_key = 1
    for factor in factors:
        base_key = (base_key * factor) % n
    
    # Adjustment based on number of factors
    adjustment = len(factors) % n
    private_key = (base_key + adjustment) % n
    
    # Generate public point using curve multiplication
    try:
        pub_point = private_key * G  # Scalar multiplication
        pub_x = pub_point.x
        pub_x_hex = hex(pub_x)[2:].zfill(64).lower()
        
        # Check if x is in only_x.txt
        if pub_x_hex in x_coords:
            print(f"Found match! x: {x_hex[:8]}, y: {y_hex[:8]}, Private key: {hex(private_key)[2:].zfill(64)}, Public x: {pub_x_hex}")
            return True
    except Exception as e:
        return False
    
    return False

# Main execution with multiprocessing
if __name__ == "__main__":
    public_keys = read_public_keys("allpubs.txt")
    x_coords = read_only_x("only_x.txt")
    
    # Use all available CPU cores
    num_processes = cpu_count()
    with Pool(processes=num_processes) as pool:
        args = [(x_hex, y_hex, x_coords) for x_hex, y_hex in public_keys]
        results = pool.map(prime_factor_derivation, args)
    
    if not any(results):
        print(f"No matches found after testing {len(public_keys)} keys across {num_processes} processes.")
