#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <secp256k1.h>
#include <boost/multiprecision/cpp_int.hpp>

//  g++ -std=c++17 -O3 -pthread keysearch.cpp -lsecp256k1 -lboost_system -o keysearch

using namespace boost::multiprecision;

// Secp256k1 context
secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

// Global variables for multithreading
std::mutex mtx;
std::atomic<bool> found(false);
std::unordered_map<std::string, cpp_int> points_map;

struct Point {
    cpp_int x;
    cpp_int y;
    
    bool operator==(const Point& other) const {
        return x == other.x && y == other.y;
    }
};

struct Result {
    Point pubkey;
    cpp_int privkey;
    std::string status;
};

// Secp256k1 curve parameters
const cpp_int p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const cpp_int n("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const Point G = {
    cpp_int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    cpp_int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
};

cpp_int mod(const cpp_int& a, const cpp_int& m) {
    cpp_int result = a % m;
    return result >= 0 ? result : result + m;
}

void extended_gcd(const cpp_int& a, const cpp_int& b, cpp_int& gcd, cpp_int& x, cpp_int& y) {
    if (b == 0) {
        gcd = a;
        x = 1;
        y = 0;
    } else {
        extended_gcd(b, a % b, gcd, y, x);
        y -= (a / b) * x;
    }
}

cpp_int inverse_mod(const cpp_int& a, const cpp_int& m) {
    cpp_int gcd, x, y;
    extended_gcd(a, m, gcd, x, y);
    if (gcd != 1) {
        return 0;
    } else {
        return mod(x, m);
    }
}

Point point_add(const Point& a, const Point& b) {
    if (a.x == 0 && a.y == 0) return b;
    if (b.x == 0 && b.y == 0) return a;
    if (a.x == b.x && a.y != b.y) return {0, 0};

    cpp_int lambda;
    if (a.x == b.x && a.y == b.y) {
        cpp_int inv = inverse_mod(2 * a.y, p);
        lambda = mod(3 * a.x * a.x * inv, p);
    } else {
        cpp_int inv = inverse_mod(b.x - a.x, p);
        lambda = mod((b.y - a.y) * inv, p);
    }

    cpp_int x = mod(lambda * lambda - a.x - b.x, p);
    cpp_int y = mod(lambda * (a.x - x) - a.y, p);
    return {x, y};
}

Point point_neg(const Point& pnt) {
    return {pnt.x, mod(-pnt.y, p)};
}

Point scalar_mult(const Point& pnt, const cpp_int& k) {
    Point result = {0, 0};
    Point addend = pnt;

    for (cpp_int i = k; i > 0; i >>= 1) {
        if ((i & 1) > 0) {
            result = point_add(result, addend);
        }
        addend = point_add(addend, addend);
    }
    return result;
}

void load_points(const std::string& filename) {
    std::cout << "Loading points from " << filename << "...\n";
    std::ifstream file(filename);
    std::string line;
    size_t count = 0;
    
    while (std::getline(file, line)) {
        size_t comma1 = line.find(',');
        size_t comma2 = line.find(',', comma1 + 1);
        if (comma1 == std::string::npos || comma2 == std::string::npos) continue;

        try {
            cpp_int x(line.substr(0, comma1));
            cpp_int y(line.substr(comma1 + 1, comma2 - comma1 - 1));
            cpp_int k(line.substr(comma2 + 1));

            std::string key = x.str() + "," + y.str();
            points_map[key] = k;
            count++;
            
            if (count % 10000 == 0) {
                std::cout << "Loaded " << count << " points...\n";
            }
        } catch (...) {
            std::cerr << "Warning: Invalid line format: " << line << "\n";
        }
    }
    std::cout << "Total points loaded: " << count << "\n";
}

std::vector<Point> load_targets(const std::string& filename) {
    std::cout << "Loading targets from " << filename << "...\n";
    std::vector<Point> targets;
    std::ifstream file(filename);
    std::string line;
    size_t count = 0;
    
    while (std::getline(file, line)) {
        line.erase(std::remove(line.begin(), line.end(), '('), line.end());
        line.erase(std::remove(line.begin(), line.end(), ')'), line.end());
        size_t comma = line.find(',');
        if (comma == std::string::npos) continue;

        try {
            cpp_int x(line.substr(0, comma));
            cpp_int y(line.substr(comma + 1));
            targets.push_back({x, y});
            count++;
        } catch (...) {
            std::cerr << "Warning: Invalid line format: " << line << "\n";
        }
    }
    std::cout << "Total targets loaded: " << count << "\n";
    return targets;
}

void search_range(const Point& target, const cpp_int& start, const cpp_int& end, cpp_int& found_key) {
    Point current = target;
    Point minus_G = point_neg(G);
    cpp_int i = start;
    // auto last_report = std::chrono::steady_clock::now();
    
    // Fast-forward to start position
    current = point_add(current, scalar_mult(minus_G, start));
    
    while (i < end && !found) {
        std::string key = current.x.str() + "," + current.y.str();
        
        {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = points_map.find(key);
            if (it != points_map.end()) {
                found_key = it->second + i;
                found = true;
                return;
            }
        }
        
        current = point_add(current, minus_G);
        i++;
        
        // Report progress every second
        // auto now = std::chrono::steady_clock::now();
        // if (std::chrono::duration_cast<std::chrono::seconds>(now - last_report).count() >= 1) {
        //     std::lock_guard<std::mutex> lock(mtx);
        //     std::cout << "Thread " << std::this_thread::get_id() 
        //               << " at iteration " << i << " (" << (i - start) << " iterations done)\n";
        //     last_report = now;
        // }
    }
}

cpp_int parallel_search(const Point& target, int num_threads) {
    const cpp_int max_iter = 100000000;
    const cpp_int chunk_size = max_iter / num_threads;
    std::vector<std::thread> threads;
    std::vector<cpp_int> results(num_threads, 0);
    
    std::cout << "Starting parallel search with " << num_threads << " threads\n";
    std::cout << "Max iterations per thread: " << chunk_size << "\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_threads; ++i) {
        cpp_int start = i * chunk_size;
        cpp_int end = (i == num_threads - 1) ? max_iter : (i + 1) * chunk_size;
        threads.emplace_back(search_range, std::ref(target), start, end, std::ref(results[i]));
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    for (cpp_int key : results) {
        if (key != 0) {
            std::cout << "\nSearch completed in " << elapsed.count() << " seconds\n";
            return key;
        }
    }
    
    std::cout << "\nNo match found after " << max_iter << " iterations ("
              << elapsed.count() << " seconds)\n";
    return 0;
}

int main() {
    try {
        // Load data
        auto start_time = std::chrono::high_resolution_clock::now();
        load_points("points.txt");
        auto targets = load_targets("allpubs.txt");
        
        // Determine thread count
        unsigned num_threads = std::thread::hardware_concurrency();
        std::cout << "\nUsing " << num_threads << " threads\n";
        
        // Process each target
        std::vector<Result> results;
        for (const auto& target : targets) {
            std::cout << "\n========================================";
            std::cout << "\nSearching for pubkey:\nX: " << target.x << "\nY: " << target.y << "\n";
            
            found = false;
            auto search_start = std::chrono::high_resolution_clock::now();
            cpp_int privkey = parallel_search(target, num_threads);
            auto search_end = std::chrono::high_resolution_clock::now();
            
            Result res;
            res.pubkey = target;
            res.privkey = privkey;
            
            if (privkey != 0) {
                Point calculated_pub = scalar_mult(G, privkey);
                res.status = (calculated_pub == target) ? "VERIFIED" : "UNVERIFIED";
                std::cout << "Found private key: " << privkey << " (" << res.status << ")\n";
            } else {
                res.status = "NOT FOUND";
                std::cout << "Private key not found\n";
            }
            
            std::chrono::duration<double> search_elapsed = search_end - search_start;
            std::cout << "Search time: " << search_elapsed.count() << " seconds\n";
            
            results.push_back(res);
        }
        
        // Save results
        std::ofstream out("results.txt");
        out << "Search Results:\n\n";
        for (const auto& res : results) {
            out << "Public Key:\nX: " << res.pubkey.x << "\nY: " << res.pubkey.y << "\n"
                << "Private Key: " << (res.privkey != 0 ? res.privkey.str() : "None") << "\n"
                << "Status: " << res.status << "\n"
                << "----------------------------------------\n";
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> total_elapsed = end_time - start_time;
        std::cout << "\nTotal execution time: " << total_elapsed.count() << " seconds\n";
        
        secp256k1_context_destroy(ctx);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}