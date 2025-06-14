from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import os

# Initialize curve
curve = SECP256k1.curve
G = SECP256k1.generator
order = SECP256k1.order
p = curve.p()

# Given public key
x = 114823904526660730388550042613781617318641730939511157851365191909881925058661
y = 110353435125110261342384183394901526212919902950843751899531649102572365749755
Q = Point(curve, x, y)

def find_private_key_from_file(Q, filename="allpubs.txt"):
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
                    return line_number
            
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
                    return candidate
    
    print("\nNo match found in file")
    return None

# Execute the search
private_key = find_private_key_from_file(Q)

if private_key is not None:
    print(f"\nRESULT: Private key found: {private_key}")
    print(f"Verification: {private_key * G == Q}")
else:
    print("\nRESULT: No private key found through file search")

# Additional information
print("\nAdditional information:")
print(f"Curve prime (p): {p}")
print(f"Curve order (n): {order}")
print(f"Target Q.x: {x}")
print(f"Target Q.y: {y}")
print(f"Q.x as hex: {hex(x)}")
print(f"Q.y as hex: {hex(y)}")