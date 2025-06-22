import time
import multiprocessing
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import PointJacobi
import random

# Initialize curve parameters
curve = SECP256k1
G = curve.generator
n = curve.order
p = curve.curve.p()

def generate_random_points(num_points, filename="points.txt"):
    """Generate random public keys and save to file"""
    with open(filename, "w") as f:
        for _ in range(num_points):
            priv = random.randint(n//2, n-1)
            pub_point = G * priv
            f.write(f"{pub_point.x()},{pub_point.y()},{priv}\n")

# Global variables for multiprocessing
manager = multiprocessing.Manager()
found_flag = manager.Value('i', 0)
result_dict = manager.dict()

def load_targets(filename="allpubs.txt"):
    """Load target public keys from file"""
    targets = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip().replace("(", "").replace(")", "")
            if line:
                x, y = map(int, line.split(','))
                targets.append((x, y))
    return targets

def load_points(filename="points.txt"):
    """Load generated points from file"""
    points = {}
    with open(filename, "r") as f:
        for line in f:
            x, y, k = map(int, line.strip().split(','))
            points[(x, y)] = k
    return points

def search_worker(target_x, target_y, points, max_iter, start_counter, end_counter, process_num):
    """Worker function for parallel search"""
    try:
        current_point = PointJacobi(curve.curve, target_x, target_y, 1, n)
    except:
        return None
    
    minus_G = PointJacobi(curve.curve, G.x(), (-G.y()) % p, 1, n)
    
    # Adjust starting point
    current_point += minus_G * start_counter
    
    for counter in range(start_counter, end_counter):
        if found_flag.value:
            return None
            
        coords = (current_point.x(), current_point.y())
        if coords in points:
            result_dict[process_num] = (points[coords] + counter, counter)
            found_flag.value = 1
            return points[coords] + counter
        
        current_point += minus_G
        
        if counter % 10000 == 0:
            print(f"Process {process_num} checked {counter} iterations...")
    
    return None

def parallel_search(target_x, target_y, points, max_iter=9000000, num_processes=4):
    """Parallelized private key search"""
    global found_flag, result_dict
    
    # Reset shared variables
    found_flag.value = 0
    result_dict.clear()
    
    # Calculate work distribution
    chunk_size = max_iter // num_processes
    ranges = [(i*chunk_size, (i+1)*chunk_size) for i in range(num_processes)]
    ranges[-1] = (ranges[-1][0], max_iter)  # Ensure we cover full range
    
    print(f"\nStarting parallel search with {num_processes} processes...")
    start_time = time.time()
    
    pool = multiprocessing.Pool(processes=num_processes)
    results = []
    
    for i, (start, end) in enumerate(ranges):
        res = pool.apply_async(search_worker, 
                              (target_x, target_y, points, max_iter, start, end, i))
        results.append(res)
    
    pool.close()
    pool.join()
    
    elapsed = time.time() - start_time
    
    if result_dict:
        priv_key = next(iter(result_dict.values()))[0]
        iterations = next(iter(result_dict.values()))[1]
        print(f"Found private key in {iterations} iterations")
        print(f"Total search time: {elapsed:.2f} seconds")
        return priv_key
    else:
        print(f"No match found (searched {max_iter} iterations)")
        print(f"Total search time: {elapsed:.2f} seconds")
        return None

def main():
    # Generate test dataset (uncomment when needed)
    print("Generating points...")
    # generate_random_points(2000000, "points.txt")
    
    print("Loading targets...")
    targets = load_targets()
    print(f"Loaded {len(targets)} target public keys")
    
    print("Loading points...")
    points = load_points()
    print(f"Loaded {len(points)} generated points")
    
    print("\nStarting search...")
    results = []
    num_processes = multiprocessing.cpu_count()
    
    for i, (x, y) in enumerate(targets, 1):
        print(f"\nTarget {i}/{len(targets)}: ({x},\n{y})")
        
        priv = parallel_search(x, y, points, num_processes=num_processes)
        
        if priv:
            # Verification
            pub = G * priv
            status = "VERIFIED" if (pub.x() == x and pub.y() == y) else "UNVERIFIED"
            print(f"Found private key: {priv} ({status})")
        else:
            status = "NOT FOUND"
            print("No match found")
        
        results.append((x, y, priv, status))
    
    # Save results
    with open("results.txt", "w") as f:
        f.write("Search Results:\n\n")
        for x, y, priv, status in results:
            f.write(f"Public Key: ({x},\n{y})\n")
            f.write(f"Private Key: {priv}\n")
            f.write(f"Status: {status}\n")
            f.write("-"*50 + "\n")
    
    print("\nSearch complete. Results saved to results.txt")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()