from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import random
import os
import sys
import time
import math
from tqdm import tqdm
import json
from multiprocessing import Pool

# Initialize curve
curve = SECP256k1.curve
G = SECP256k1.generator
order = SECP256k1.order
p = curve.p()

# Read public keys from allpubs.txt (x,y in decimal)
def read_public_keys(filename="allpubs.txt"):
    public_keys = []
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found!")
        return []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if ',' in line:
                parts = line.split(',')
                try:
                    x = int(parts[0].strip())
                    y = int(parts[1].strip())
                    public_keys.append(Point(curve, x, y))
                except ValueError:
                    continue
    return public_keys

# Read x-coordinates from only_x.txt
def read_only_x(filename="only_x.txt"):
    x_coords = set()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found!")
        return x_coords
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip().lower()
            if len(line) in (63, 64) and all(c in '0123456789abcdef' for c in line):
                if len(line) == 63:
                    line = '0' + line
                x_coords.add(int(line, 16))
    return x_coords

def is_point_on_curve(x, y, curve):
    """Check if a point (x,y) is on the elliptic curve"""
    try:
        Point(curve, x, y)
        return True
    except:
        return False

def optimized_combinatorial_search(Q, num_terms=20, min_val=2**247, max_val=order, samples=833333):
    """
    Optimized combinatorial search for high-value terms with modulo correction
    """
    avg_val = (min_val + max_val) // 2
    expected_sum = num_terms * avg_val
    range_size = max_val - min_val
    
    print(f"Starting optimized search for Q(x={Q.x()}, y={Q.y()}) with {num_terms} terms...")
    print(f"Min value: {min_val} (2^{math.log2(min_val):.1f})")
    print(f"Max value: {max_val} (2^{math.log2(max_val):.1f})")
    print(f"Expected sum: {expected_sum:.2e} (2^{math.log2(expected_sum):.1f})")
    print(f"Sample size: {samples}")
    
    best_distance_sq = float('inf')
    best_combination = None
    best_k = None
    
    pbar = tqdm(total=samples, desc="Sampling combinations", ncols=80)
    for _ in range(samples):
        combination = [random.randint(min_val, max_val) for _ in range(num_terms)]
        k = sum(combination) % order  # Modulo to stay within curve order
        
        try:
            P = k * G
        except:
            pbar.update(1)
            continue
            
        dx = P.x() - Q.x()
        dy = P.y() - Q.y()
        distance_sq = dx*dx + dy*dy
        
        if distance_sq < best_distance_sq:
            best_distance_sq = distance_sq
            best_combination = combination
            best_k = k
            best_distance = math.sqrt(distance_sq)
            pbar.set_description(f"Best dist: {best_distance:.1e}")
            
            if distance_sq == 0:
                pbar.close()
                return k, combination
        
        pbar.update(1)
    
    pbar.close()
    
    if best_combination:
        print(f"Best candidate (distance {best_distance:.2e}):")
        print(f"Sum: {best_k}")
        print(f"Combination (first 5 terms): {best_combination[:5]}")
        return best_k, best_combination
    
    return None, None

def parallel_search_worker(args):
    """Worker function for parallel processing"""
    Q, task_id, num_tasks, num_terms, min_val, max_val, samples = args
    random.seed(int(time.time()) + task_id)
    
    print(f"Worker {task_id} starting with {samples} samples...")
    return optimized_combinatorial_search(Q, num_terms, min_val, max_val, samples)

def parallel_combinatorial_search_for_all(Q_list, x_coords, num_terms=20, min_val=2**247, max_val=order, 
                                          total_samples=1000, num_workers=8):
    results = {}
    start_time = time.time()
    duration = 24 * 3600  # 24 hours
    samples_per_worker = total_samples // num_workers
    
    for idx, Q in enumerate(Q_list):
        if time.time() - start_time > duration:
            break
            
        if Q.x() not in x_coords:
            continue
            
        print(f"\nProcessing public key {idx + 1}/{len(Q_list)}: (x={Q.x()}, y={Q.y()})")
        tasks = [(Q, i, num_workers, num_terms, min_val, max_val, samples_per_worker) 
                 for i in range(num_workers)]
        
        with Pool(num_workers) as pool:
            results_list = pool.map(parallel_search_worker, tasks)
        
        best_k = None
        best_combination = None
        best_distance_sq = float('inf')
        
        for k, combination in results_list:
            if k is not None:
                P = k * G
                dx = P.x() - Q.x()
                dy = P.y() - Q.y()
                distance_sq = dx*dx + dy*dy
                if distance_sq < best_distance_sq:
                    best_distance_sq = distance_sq
                    best_k = k
                    best_combination = combination
        
        if best_k:
            try:
                computed_P = best_k * G
                if computed_P == Q:
                    results[Q] = best_k
                    print(f"Private key found: {best_k} for public key (x={Q.x()}, y={Q.y()})")
            except Exception as e:
                print(f"Verification failed for Q(x={Q.x()}, y={Q.y()}): {e}")
        else:
            print(f"No private key found for (x={Q.x()}, y={Q.y()}) with current search")
    
    return results

def save_progress(results, filename="progress.json"):
    with open(filename, 'w') as f:
        json.dump({f"{k.x()},{k.y()}": v for k, v in results.items()}, f)

# Main execution
if __name__ == "__main__":
    print("=" * 80)
    print("Optimized High-Value Combinatorial Search for All Keys")
    print("=" * 80)
    
    public_keys = read_public_keys()
    x_coords = read_only_x()
    
    if not public_keys or not x_coords:
        print("Error: Unable to proceed due to missing files or data.")
        sys.exit(1)
    
    print(f"Loaded {len(public_keys)} public keys and {len(x_coords)} x-coordinates.")
    start_time = time.time()
    
    results = parallel_combinatorial_search_for_all(public_keys, x_coords)
    save_progress(results)
    
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 80)
    print("Final Results")
    print("=" * 80)
    if results:
        for Q, private_key in results.items():
            print(f"Public key (x={Q.x()}, y={Q.y()}) -> Private key: {private_key}")
    else:
        print(f"No matches found after {elapsed_time:.0f} seconds.")
    
    print("\n" + "=" * 80)
    print("Diagnostic Information")
    print("=" * 80)
    print(f"Total time: {elapsed_time:.2f} seconds")
    print(f"Curve order: {order}")
    print(f"Number of public keys processed: {len(public_keys)}")