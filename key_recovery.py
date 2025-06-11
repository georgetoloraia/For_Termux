import os
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey
from multiprocessing import Pool, cpu_count
import binascii

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
                x_hex = hex(x_dec)[2:].zfill(64).lower()  # Convert to 64-char hex
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

# Generate private key with various mathematical operations and check match
def check_private_key(args):
    x_hex, y_hex, x_coords = args
    x_int = int(x_hex, 16)
    y_int = int(y_hex, 16)
    
    # Concatenate x and y
    concatenated = x_hex + y_hex
    concatenated_int = int(concatenated, 16)
    
    # Reverse concatenated
    reversed_concat = concatenated[::-1]
    modified_concatenate = concatenated + reversed_concat
    modified_int = int(modified_concatenate, 16)
    
    # Expanded list of mathematical operations to try
    operations = [
        lambda a, b, c: (a + int(b, 16) + c) % n,  # Add y
        lambda a, b, c: (a - int(b, 16) + c) % n,  # Subtract y
        lambda a, b, c: (a * int(b, 16) + c) % n,  # Multiply by y
        lambda a, b, c: (a // int(b, 16) + c) % n if int(b, 16) != 0 else a + c,  # Divide by y (modulo-safe)
        lambda a, b, c: (a + int(b, 16) * c) % n,  # y * x + modified
        lambda a, b, c: (a ** 2 + c) % n,  # Square modified
        lambda a, b, c: (a ** 3 + c) % n,  # Cube modified
        lambda a, b, c: (a ^ int(b, 16) + c) % n,  # XOR with y
        lambda a, b, c: (a & int(b, 16) + c) % n,  # AND with y
        lambda a, b, c: (a | int(b, 16) + c) % n,  # OR with y
        lambda a, b, c: ((a + int(b, 16)) * c) % n,  # (x + y) * modified
        lambda a, b, c: ((a - int(b, 16)) * c) % n,  # (x - y) * modified
        lambda a, b, c: (a % int(b, 16) + c) % n if int(b, 16) != 0 else a + c,  # Modulus with y
        lambda a, b, c: ((a << 4) + c) % n,  # Left shift by 4
        lambda a, b, c: ((a >> 4) + c) % n,  # Right shift by 4
        lambda a, b, c: ((~a) + c) % n,  # Bitwise NOT
        lambda a, b, c: (int(b, 16) * a + c) % n,  # y * modified + x
        lambda a, b, c: ((a + c) * int(b, 16)) % n,  # (modified + x) * y
    ]
    
    # Test each operation
    for op in operations:
        private_key = op(modified_int, y_hex, x_int) % n
        
        # Generate public point using curve multiplication
        try:
            pub_point = private_key * G  # Scalar multiplication
            pub_x = pub_point.x
            pub_x_hex = hex(pub_x)[2:].zfill(64).lower()
            
            # Check if x is in only_x.txt
            if pub_x_hex in x_coords:
                print(f"Found match! Operation: {op.__name__}, Private key: {hex(private_key)[2:].zfill(64)}, Public x: {pub_x_hex}")
                return True
        except Exception as e:
            continue  # Skip invalid operations (e.g., division by zero)
    
    return False

# Main execution with multiprocessing
if __name__ == "__main__":
    public_keys = read_public_keys("allpubs.txt")
    x_coords = read_only_x("only_x.txt")
    
    # Use all available CPU cores
    num_processes = cpu_count()
    with Pool(processes=num_processes) as pool:
        args = [(x_hex, y_hex, x_coords) for x_hex, y_hex in public_keys]
        results = pool.map(check_private_key, args)
    
    if not any(results):
        print(f"No matches found after testing {len(public_keys)} keys across {num_processes} processes.")