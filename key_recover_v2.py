import os
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey
from multiprocessing import Pool, cpu_count
import binascii
import time

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

# Differential sequence with enhanced adjustment
def differential_sequence_with_adjustment(args):
    i, (x_hex, y_hex), x_coords, cycle, cumulative_y_sum = args
    x_int = int(x_hex, 16)
    y_int = int(y_hex, 16)
    
    # Compute difference with next x cyclically
    next_x_int = int(public_keys[(i + 1) % len(public_keys)][0], 16)
    diff = (next_x_int - x_int) % n
    
    # Dynamic adjustment with cycle and non-linear increment
    adjustment = (cumulative_y_sum * ((i + cycle * (i % 5 + 1)) % 20 + 1)) % n
    
    # Extended adjustment range
    for adjust in range(-20, 21):  # Range of 41 adjustments
        private_key = (diff * (i + 1) + adjustment + adjust) % n
        
        # Generate public point using curve multiplication
        try:
            pub_point = private_key * G  # Scalar multiplication
            pub_x = pub_point.x
            pub_x_hex = hex(pub_x)[2:].zfill(64).lower()
            
            # Check if x is in only_x.txt
            if pub_x_hex in x_coords:
                print(f"Found match! Cycle: {cycle}, i: {i}, x: {x_hex[:8]}, y: {y_hex[:8]}, Adjust: {adjust}, Adjustment: {adjustment}, Private key: {hex(private_key)[2:].zfill(64)}, Public x: {pub_x_hex}")
                return True
        except Exception as e:
            continue
    
    return False

# Main execution with 24-hour loop
if __name__ == "__main__":
    public_keys = read_public_keys("allpubs.txt")
    x_coords = read_only_x("only_x.txt")
    
    # Calculate cumulative sum of y-coordinates modulo n
    cumulative_y_sum = sum(int(key[1], 16) for key in public_keys) % n
    
    # Set 24-hour duration (86,400 seconds) from start time
    start_time = time.time()  # Use current time as start
    duration = 24 * 3600  # 24 hours in seconds
    
    cycle = 0
    total_tests = 0  # Resume from your last reported 102,366,810
    
    # Use all available CPU cores
    num_processes = cpu_count()
    
    while time.time() - start_time < duration:
        with Pool(processes=num_processes) as pool:
            args = [(i, key, x_coords, cycle, cumulative_y_sum) for i, key in enumerate(public_keys)]
            results = pool.map(differential_sequence_with_adjustment, args)
            
            total_tests += len(public_keys) * 41  # Each key tested with 41 adjustments
            if any(results):
                print(f"Total candidates tested: {total_tests}")
                break
        
        cycle += 1  # Increment cycle with non-linear variation
        elapsed_time = time.time() - start_time
        print(f"Completed cycle {cycle}, elapsed time: {elapsed_time:.0f} seconds, total tests: {total_tests}")
    
    if time.time() - start_time >= duration:
        print(f"No matches found after 24 hours. Total candidates tested: {total_tests} across {num_processes} processes.")
