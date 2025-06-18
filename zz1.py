from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import random
import os
import time
from tqdm import tqdm
import json
from multiprocessing import Pool
from collections import Counter
import sys
import math

# Initialize curve
curve = SECP256k1.curve
G = SECP256k1.generator
order = SECP256k1.order
p = curve.p()

# Read public keys from allpubs.txt (x,y in decimal) and extract x-coordinates
def read_public_keys(filename="allpubs.txt"):
    public_keys = []
    all_x_coords = set()
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found!")
        return [], all_x_coords
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if ',' in line:
                parts = line.split(',')
                try:
                    x = int(parts[0].strip())
                    y = int(parts[1].strip())
                    public_keys.append(Point(curve, x, y))
                    all_x_coords.add(x)
                except ValueError:
                    continue
    return public_keys, all_x_coords

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

def analyze_y_coordinates(public_keys):
    """Analyze y-coordinate properties"""
    y_values = [Q.y() for Q in public_keys]
    parity = [y % 2 for y in y_values]
    parity_count = Counter(parity)
    print(f"\nY-coordinate analysis:")
    print(f"Parity distribution: {parity_count}")
    if parity_count.get(0, 0) == len(public_keys):
        print("All y-coordinates are even; constraining k to even values.")
        return 0
    elif parity_count.get(1, 0) == len(public_keys):
        print("All y-coordinates are odd; constraining k to odd values.")
        return 1
    print("Mixed parity; no k constraint from y.")
    return None

def binary_segment_search(Q, segment_start, segment_end, samples=2500000000, k_parity=None):
    segment_size = segment_end - segment_start
    print(f"Searching segment {segment_start}-{segment_end} for Q(x={Q.x()}, y={Q.y()}) with {samples} samples...")
    print(f"k parity constraint: {k_parity}")
    
    best_distance_sq = float('inf')
    best_k_segment = None
    best_combination = None
    
    pbar = tqdm(total=samples, desc=f"Segment {segment_start}-{segment_end}", ncols=80)
    for i in range(samples):
        # Generate k as a geometric progression starting from 2^134
        base_k = (2 ** 134) * (1 + i * 0.01)
        k = int(base_k + random.randint(0, 2**(segment_end - segment_start) - 1)) % order
        
        if k_parity is not None:
            while k % 2 != k_parity:
                k = (k + 1) % order
        
        try:
            # Checkpoint 1: Multiplication k * G
            P = k * G
            if P.x() is None:
                pbar.update(1)
                continue
            
            # Checkpoint 2: Addition (e.g., P + G for testing)
            P_added = P + G
            if P_added.x() is None:
                pbar.update(1)
                continue
            
            # Check matches at checkpoints
            if P.x() in all_x_coords:
                print(f"Match found at multiplication checkpoint: k={k}, x={P.x()}")
                return k, bin(k)[2:].zfill(256)[-segment_size:], segment_start, segment_end
            if P_added.x() in all_x_coords:
                print(f"Match found at addition checkpoint: k={k}, x={P_added.x()}")
                return k, bin(k)[2:].zfill(256)[-segment_size:], segment_start, segment_end
            
        except:
            pbar.update(1)
            continue
            
        dx = P.x() - Q.x()
        dy = P.y() - Q.y()
        distance_sq = dx*dx + dy*dy
        
        if distance_sq < best_distance_sq:
            best_distance_sq = distance_sq
            best_k_segment = k
            best_combination = [bit for bit in bin(k)[2:].zfill(256)[-segment_size:]]
        
        best_distance = math.sqrt(best_distance_sq)
        pbar.set_description(f"Best dist: {best_distance:.1e}")
        
        pbar.update(1)
    
    pbar.close()
    
    if best_combination:
        print(f"Best candidate (distance {math.sqrt(best_distance_sq):.2e}):")
        print(f"Segment k: {best_k_segment}")
    return best_k_segment, best_combination, None, None, None, None, segment_start, segment_end

def parallel_segment_search_worker(args):
    global all_x_coords  # Ensure access to all_x_coords
    Q, task_id, num_tasks, segment_start, segment_end, samples, k_parity = args
    random.seed(int(time.time()) + task_id)
    return binary_segment_search(Q, segment_start, segment_end, samples, k_parity)

def parallel_segmented_search_for_all(Q_list, x_coords, all_x_coords, segments=[(134, 160), (160, 192), (192, 224), (224, 256)], 
                                     total_samples=10000000000, num_workers=8):
    results = {}
    start_time = time.time()
    duration = 24 * 3600  # 24 hours
    samples_per_segment = max(1, total_samples // len(segments) // num_workers)
    
    print(f"Total samples: {total_samples}, Segments: {len(segments)}, Workers: {num_workers}, Samples per segment per worker: {samples_per_segment}")
    k_parity = analyze_y_coordinates(Q_list)
    
    for idx, Q in enumerate(Q_list):
        if time.time() - start_time > duration:
            break
        if Q.x() not in x_coords:
            continue
        print(f"\nProcessing public key {idx + 1}/{len(Q_list)}: (x={Q.x()}, y={Q.y()})")
        segment_results = {}
        
        for segment_start, segment_end in segments:
            tasks = [(Q, i, num_workers, segment_start, segment_end, samples_per_segment, k_parity) 
                     for i in range(num_workers)]
            with Pool(num_workers) as pool:
                results_list = pool.map(parallel_segment_search_worker, tasks)
            
            best_result = min((r for r in results_list if r[0] is not None), default=(None, None, None, None, None, None, None, None),
                              key=lambda x: abs(x[0] % (2**(x[7] - x[6]))) if x[0] is not None else float('inf'))
            if best_result[0]:
                segment_results[(segment_start, segment_end)] = (best_result[0], best_result[1])
        
        if segment_results:
            candidate_k = 0
            for (start, end), (best_k, best_comb) in sorted(segment_results.items()):
                shift = 256 - end
                if shift < 0:
                    shift = 0
                mask = (1 << (end - start)) - 1
                segment_value = best_k % (1 << (end - start))
                candidate_k |= (segment_value << shift)
            
            candidate_k &= (1 << 256) - 1
            
            for k in [candidate_k, candidate_k - 2, candidate_k - 1, candidate_k + 1, candidate_k + 2]:
                k = k % order if k >= 0 else order + k
                try:
                    computed_P = k * G
                    computed_x = computed_P.x()
                    if computed_x in all_x_coords:
                        results[Q] = k
                        print(f"Private key found: {k} for public key (x={Q.x()}, y={Q.y()}), x match: {computed_x}")
                        break
                except Exception as e:
                    print(f"Verification failed for k={k}, Q(x={Q.x()}, y={Q.y()}): {e}")
            else:
                print(f"No x match for candidate_k={candidate_k}, computed x={computed_x}")
        else:
            print(f"No private key found for (x={Q.x()}, y={Q.y()}) with segmented search")
    
    return results

def save_progress(results, filename="progress.json"):
    with open(filename, 'w') as f:
        json.dump({f"{k.x()},{k.y()}": v for k, v in results.items()}, f)

if __name__ == "__main__":
    print("=" * 80)
    print("Checkpoint-Enabled Segmented Search with 134-256 Focus")
    print("=" * 80)
    
    public_keys, all_x_coords = read_public_keys()
    x_coords = read_only_x()
    
    if not public_keys or not x_coords:
        print("Error: Unable to proceed due to missing files or data.")
        sys.exit(1)
    
    print(f"Loaded {len(public_keys)} public keys and {len(x_coords)} x-coordinates.")
    print(f"Total unique x-coordinates in allpubs: {len(all_x_coords)}")
    start_time = time.time()
    
    results = parallel_segmented_search_for_all(public_keys, x_coords, all_x_coords, 
                                               segments=[(134, 160), (160, 192), (192, 224), (224, 256)], 
                                               total_samples=1000000000)
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
    print(f"Total samples: {10000000000}")