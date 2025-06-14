from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import itertools
import os
import sys
import math

# Initialize curve
curve = SECP256k1.curve
G = SECP256k1.generator
order = SECP256k1.order
p = curve.p()

# Given public key
x = 114823904526660730388550042613781617318641730939511157851365191909881925058661
y = 110353435125110261342384183394901526212919902950843751899531649102572365749755
Q = Point(curve, x, y)

def combinatorial_search(Q, max_terms=5, min_val=1, max_val=1000, print_interval=100000):
    """Combinatorial search with configurable parameters"""
    print(f"\nStarting combinatorial search with max_terms={max_terms}, min_val={min_val}, max_val={max_val}")
    
    # Precompute points for integers min_val to max_val
    print(f"Precomputing points for values {min_val} to {max_val}...")
    points = {}
    for i in range(min_val, max_val + 1):
        points[i] = i * G
        if i % print_interval == 0:
            sys.stdout.write(f"\rPrecomputed up to {i}/{max_val}")
            sys.stdout.flush()
    print("\nPrecomputation complete")
    
    # Check single terms
    print("\nChecking single terms...")
    for i in range(min_val, max_val + 1):
        if i % print_interval == 0:
            print(f"Checking term: {i}")
        if points[i] == Q:
            print(f"Found solution with single term: {i}")
            return i, [i]
    
    # Check combinations of multiple terms
    for num_terms in range(2, max_terms + 1):
        print(f"\nChecking combinations of {num_terms} terms...")
        total_combinations = math.comb(max_val - min_val + 1, num_terms)
        print(f"Total combinations to check: {total_combinations}")
        
        count = 0
        for comb in itertools.combinations(range(min_val, max_val + 1), num_terms):
            count += 1
            
            # Print progress
            if count % print_interval == 0:
                sys.stdout.write(f"\rChecked {count}/{total_combinations} combinations")
                sys.stdout.flush()
                print(f" | Current: {comb}")
            
            # Skip if sum exceeds curve order
            comb_sum = sum(comb)
            if comb_sum > order:
                continue
                
            # Compute point sum for combination
            try:
                P = points[comb[0]]
                for i in comb[1:]:
                    P += points[i]
                
                # Check for match
                if P == Q:
                    print(f"\nFOUND SOLUTION! Terms: {comb} -> k = {comb_sum}")
                    print(f"Combination: {' + '.join(str(t) for t in comb)}G = Q")
                    return comb_sum, comb
            except Exception as e:
                print(f"\nError with combination {comb}: {e}")
                continue
    
    return None, "not_found"

def find_private_key(Q, filename="allpubs.txt"):
    """Find private key by checking Q against all public keys in file"""
    # Compute negative of Q (same x, -y mod p)
    Q_neg = Point(curve, Q.x(), (-Q.y()) % p)
    
    # Counter for line numbers
    line_number = 0
    
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found!")
        return None
    
    print(f"Searching for public key in '{filename}'...")
    print(f"Target Q: ({Q.x()}, {Q.y()})")
    print(f"Negative of Q: ({Q_neg.x()}, {Q_neg.y()})")
    
    with open(filename, 'r') as f:
        for line in f:
            line_number += 1
            parts = line.strip().split(',')
            
            if len(parts) < 2:
                continue  # Skip malformed lines
            
            try:
                file_x = int(parts[0].strip())
                file_y = int(parts[1].strip())
            except ValueError:
                continue  # Skip lines with non-integer coordinates
            
            # Create point from file data
            try:
                file_point = Point(curve, file_x, file_y)
            except:
                continue  # Skip invalid points
            
            # Check for direct match (Q found in file)
            if file_point == Q:
                print(f"\nFound exact match at line {line_number}!")
                print(f"File point: ({file_x}, {file_y})")
                print(f"Assuming private key = line number: {line_number}")
                
                # Verify if line number is the private key
                if line_number * G == Q:
                    print("VERIFIED! Line number is the private key")
                    return line_number
                else:
                    print("WARNING: Line number is not the private key")
                    # Proceed to combinatorial search
                    print("Initiating combinatorial search...")
                    result, method = combinatorial_search(Q, max_terms=5, min_val=123, max_val=1000)
                    if result:
                        return result
                    else:
                        print("Combinatorial search completed without finding solution")
                        return None
            
            # Check for negative match
            if file_point == Q_neg:
                print(f"\nFound negative match at line {line_number}!")
                print(f"File point: ({file_x}, {file_y})")
                
                # The private key would be order - line_number
                candidate = (order - line_number) % order
                print(f"Candidate private key = order - line_number = {candidate}")
                
                # Verify candidate
                if candidate * G == Q:
                    print("VERIFIED! Candidate is the private key")
                    return candidate
                else:
                    print("WARNING: Candidate is not the private key")
                    # Proceed to combinatorial search
                    print("Initiating combinatorial search...")
                    result, method = combinatorial_search(Q, max_terms=5, min_val=1, max_val=1000)
                    if result:
                        return result
                    else:
                        print("Combinatorial search completed without finding solution")
                        return None
    
    print("\nNo match found in file")
    print("Initiating combinatorial search...")
    result, method = combinatorial_search(Q, max_terms=256, min_val=123, max_val=2**256)
    if result:
        return result
    else:
        print("Combinatorial search completed without finding solution")
        return None

# Execute the search
print("=" * 80)
print("Public Key Analysis")
print("=" * 80)
private_key = find_private_key(Q)

print("\n" + "=" * 80)
print("Final Results")
print("=" * 80)
if private_key is not None:
    print(f"RESULT: Private key found: {private_key}")
    print(f"Verification: {private_key * G == Q}")
else:
    print("RESULT: No private key found through any method")

# Additional information
print("\n" + "=" * 80)
print("Additional Information")
print("=" * 80)
print(f"Curve prime (p): {p}")
print(f"Curve order (n): {order}")
print(f"Target Q.x: {x}")
print(f"Target Q.y: {y}")
print(f"Q.x as hex: {hex(x)}")
print(f"Q.y as hex: {hex(y)}")
print(f"Public key on curve: {Q != Point(curve, 0, 0)}")