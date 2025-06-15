from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import random
import os
import time
import math
from tqdm import tqdm

# Initialize curve
curve = SECP256k1.curve
G = SECP256k1.generator
order = SECP256k1.order
p = curve.p()

# Given public key
x = 114823904526660730388550042613781617318641730939511157851365191909881925058661
y = 110353435125110261342384183394901526212919902950843751899531649102572365749755
Q = Point(curve, x, y)

def is_point_on_curve(x, y, curve):
    """Check if a point (x,y) is on the elliptic curve"""
    try:
        # This will raise an error if point is not on curve
        Point(curve, x, y)
        return True
    except:
        return False

def optimized_combinatorial_search(Q, num_terms=256, min_val=2**247, max_val=2**248, samples=10000):
    """
    Optimized combinatorial search for high-value terms
    Uses scalar arithmetic instead of point arithmetic for efficiency
    """
    # Calculate expected sum and range
    avg_val = (min_val + max_val) // 2
    expected_sum = num_terms * avg_val
    range_size = max_val - min_val
    
    print(f"Starting optimized search for {num_terms} terms...")
    print(f"Min value: {min_val} (2^{math.log2(min_val):.1f})")
    print(f"Max value: {max_val} (2^{math.log2(max_val):.1f})")
    print(f"Expected sum: {expected_sum:.2e} (2^{math.log2(expected_sum):.1f})")
    print(f"Sample size: {samples}")
    
    # Initialize best candidate
    best_distance_sq = float('inf')
    best_combination = None
    best_k = None
    
    # Create progress bar
    pbar = tqdm(total=samples, desc="Sampling combinations", ncols=80)
    
    for i in range(samples):
        # Generate random combination
        combination = [random.randint(min_val, max_val) for _ in range(num_terms)]
        k = sum(combination)
        
        # Skip invalid sums
        if k >= order:
            pbar.update(1)
            continue
            
        # Compute the point using scalar multiplication (more efficient)
        try:
            P = k * G
        except:
            pbar.update(1)
            continue
            
        # Calculate squared Euclidean distance (more efficient than actual distance)
        dx = P.x() - Q.x()
        dy = P.y() - Q.y()
        distance_sq = dx*dx + dy*dy
        
        # Track best candidate
        if distance_sq < best_distance_sq:
            best_distance_sq = distance_sq
            best_combination = combination
            best_k = k
            best_distance = math.sqrt(distance_sq)
            pbar.set_description(f"Best dist: {best_distance:.1e}")
            
            # Early termination if exact match
            if distance_sq == 0:
                pbar.close()
                return k, combination
        
        pbar.update(1)
    
    pbar.close()
    
    if best_combination is not None:
        print(f"Best candidate found (distance {best_distance:.2e}):")
        print(f"Sum: {best_k}")
        print(f"Combination (first 5 terms): {best_combination[:5]}")
        return best_k, best_combination
    
    return None, None

def parallel_search_worker(args):
    """Worker function for parallel processing"""
    Q, task_id, num_tasks, num_terms, min_val, max_val, samples = args
    # Adjust random seed for each worker
    random.seed(int(time.time()) + task_id)
    
    print(f"Worker {task_id} starting with {samples} samples...")
    return optimized_combinatorial_search(
        Q, 
        num_terms=num_terms,
        min_val=min_val,
        max_val=max_val,
        samples=samples
    )

def parallel_combinatorial_search(Q, num_terms=256, min_val=2**247, max_val=2**248, 
                                  total_samples=100000, num_workers=8):
    """Parallel combinatorial search using multiprocessing"""
    from multiprocessing import Pool
    
    samples_per_worker = total_samples // num_workers
    tasks = [(Q, i, num_workers, num_terms, min_val, max_val, samples_per_worker) 
             for i in range(num_workers)]
    
    print(f"Starting parallel search with {num_workers} workers...")
    print(f"Samples per worker: {samples_per_worker}")
    print(f"Total samples: {total_samples}")
    
    with Pool(num_workers) as pool:
        results = pool.map(parallel_search_worker, tasks)
    
    # Find best result across workers
    best_k = None
    best_combination = None
    best_distance_sq = float('inf')
    
    for result in results:
        k, combination = result
        if k is not None:
            P = k * G
            dx = P.x() - Q.x()
            dy = P.y() - Q.y()
            distance_sq = dx*dx + dy*dy
            
            if distance_sq < best_distance_sq:
                best_distance_sq = distance_sq
                best_k = k
                best_combination = combination
    
    if best_k is not None:
        best_distance = math.sqrt(best_distance_sq)
        print(f"\nBest candidate across all workers (distance {best_distance:.2e}):")
        print(f"Sum: {best_k}")
        print(f"Combination (first 5 terms): {best_combination[:5]}")
        return best_k, best_combination
    
    return None, None

# Execute the optimized search
print("=" * 80)
print("Optimized High-Value Combinatorial Search")
print("=" * 80)

# Start with a smaller sample size for testing
start_time = time.time()
private_key, combination = parallel_combinatorial_search(
    Q,
    num_terms=256,
    min_val=2**247,
    max_val=2**248,
    total_samples=5000000,  # Total samples across workers
    num_workers=8
)
search_time = time.time() - start_time

print("\n" + "=" * 80)
print("Search Results")
print("=" * 80)
if private_key:
    # Verify the solution
    verification_point = private_key * G
    verification = (verification_point.x() == Q.x() and verification_point.y() == Q.y())
    
    print(f"Private key found: {private_key}")
    print(f"Verification: {verification}")
    if not verification:
        print(f"Generated point: ({verification_point.x()}, {verification_point.y()})")
        print(f"Target point:    ({Q.x()}, {Q.y()})")
    print(f"Search time: {search_time:.2f} seconds")
else:
    print("No private key found in this sample")

print("\n" + "=" * 80)
print("Diagnostic Information")
print("=" * 80)
print(f"Target Q.x: {x}")
print(f"Target Q.y: {y}")
print(f"Curve order: {order}")
print(f"Q.x hex: {hex(x)}")
print(f"Q.y hex: {hex(y)}")
print(f"Public key on curve: {is_point_on_curve(x, y, curve)}")

# Additional diagnostics for the found candidate
if private_key:
    candidate_Q = private_key * G
    dx = candidate_Q.x() - x
    dy = candidate_Q.y() - y
    distance = math.sqrt(dx*dx + dy*dy)
    print(f"\nCandidate public key from combinatorial search:")
    print(f"x: {candidate_Q.x()}")
    print(f"y: {candidate_Q.y()}")
    print(f"Distance to target Q: {distance:.2e}")
    print(f"Hex difference x: {hex(abs(dx))}")
    print(f"Hex difference y: {hex(abs(dy))}")