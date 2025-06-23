#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <unordered_map>
#include <secp256k1.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <iomanip>
#include <sstream>

// g++ -std=c++17 -O3 -pthread keys.cpp -lsecp256k1 -lboost_system -o keysearch

using namespace boost::multiprecision;

// Secp256k1 context
secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

// Global variables for multithreading
std::mutex mtx;
std::atomic<bool> found(false);
std::atomic<uint64_t> total_iterations(0);

struct Point {
    cpp_int x;
    cpp_int y;
};

// Secp256k1 curve parameters
const cpp_int p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const cpp_int n("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const cpp_int range_start("21778071482940061661655974875633165533184");
const cpp_int range_end("43556142965880123323311949751266331066367");
const std::string target_compressed_pubkey = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16";

// Modular arithmetic
cpp_int mod(const cpp_int& a, const cpp_int& m) {
    cpp_int result = a % m;
    return result >= 0 ? result : result + m;
}

// Convert hex string to byte array
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        bytes.push_back(static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16)));
    }
    return bytes;
}

// Convert byte array to hex string
std::string bytes_to_hex(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// Convert cpp_int to 32-byte private key
std::vector<unsigned char> cpp_int_to_bytes(const cpp_int& num) {
    std::vector<unsigned char> bytes(32, 0);
    std::stringstream ss;
    ss << std::hex << num;
    std::string hex = ss.str();
    if (hex.substr(0, 2) == "0x") {
        hex = hex.substr(2);
    }
    if (hex.length() % 2 == 1) {
        hex = "0" + hex;
    }
    std::vector<unsigned char> temp = hex_to_bytes(hex);
    size_t offset = temp.size() > 32 ? temp.size() - 32 : 0;
    size_t copy_len = std::min(temp.size(), size_t(32));
    std::copy(temp.begin() + offset, temp.begin() + offset + copy_len, bytes.end() - copy_len);
    return bytes;
}

// Decompress public key
Point decompress_pubkey(const std::string& compressed) {
    std::vector<unsigned char> pubkey_bytes = hex_to_bytes(compressed);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_bytes.data(), pubkey_bytes.size())) {
        throw std::string("Failed to parse compressed public key");
    }

    unsigned char serialized[65];
    size_t serialized_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    std::string x_hex = bytes_to_hex(serialized + 1, 32);
    std::string y_hex = bytes_to_hex(serialized + 33, 32);
    cpp_int x("0x" + x_hex);
    cpp_int y("0x" + y_hex);
    return {x, y};
}

// Generate random private key in range
cpp_int generate_random_key(std::mt19937_64& rng) {
    cpp_int range_size = range_end - range_start + 1;
    size_t byte_count = (msb(range_size) + 7) / 8;
    std::vector<unsigned char> bytes(byte_count);
    std::uniform_int_distribution<unsigned char> byte_dist(0, 255);
    cpp_int result;
    do {
        for (auto& b : bytes) {
            b = byte_dist(rng);
        }
        std::string hex = bytes_to_hex(bytes.data(), bytes.size());
        result = cpp_int("0x" + hex);
    } while (result >= range_size);
    return range_start + result;
}

// Generate random points and save to points.txt
void generate_random_points(int num_points, const std::string& filename = "points.txt") {
    std::cout << "Generating " << num_points << " random points...\n";
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::ofstream file(filename);
    if (!file) {
        throw std::string("Failed to open points.txt for writing");
    }

    for (int i = 0; i < num_points; ++i) {
        cpp_int privkey = generate_random_key(rng);
        auto privkey_bytes = cpp_int_to_bytes(privkey);
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey_bytes.data())) {
            continue;
        }

        unsigned char serialized[65];
        size_t serialized_len = 65;
        secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        std::string x_hex = bytes_to_hex(serialized + 1, 32);
        std::string y_hex = bytes_to_hex(serialized + 33, 32);
        cpp_int x("0x" + x_hex);
        cpp_int y("0x" + y_hex);

        file << "(" << x << "," << y << "," << privkey << ")\n";

        if ((i + 1) % 1000000 == 0) {
            std::cout << "Generated " << (i + 1) << " points...\n";
        }
    }
    file.close();
    std::cout << "Generated points saved to " << filename << "\n";
}

// Load points from points.txt
std::unordered_map<std::string, std::pair<cpp_int, cpp_int>> load_points(const std::string& filename = "points.txt") {
    std::cout << "Loading points from " << filename << "...\n";
    std::unordered_map<std::string, std::pair<cpp_int, cpp_int>> points;
    std::ifstream file(filename);
    if (!file) {
        throw std::string("Failed to open points.txt for reading");
    }

    std::string line;
    size_t count = 0;
    while (std::getline(file, line)) {
        line.erase(std::remove(line.begin(), line.end(), '('), line.end());
        line.erase(std::remove(line.begin(), line.end(), ')'), line.end());
        size_t comma1 = line.find(',');
        size_t comma2 = line.find(',', comma1 + 1);
        if (comma1 == std::string::npos || comma2 == std::string::npos) {
            std::cerr << "Invalid line format: " << line << "\n";
            continue;
        }

        try {
            cpp_int x(line.substr(0, comma1));
            cpp_int y(line.substr(comma1 + 1, comma2 - comma1 - 1));
            cpp_int k(line.substr(comma2 + 1));
            points[x.str()] = {y, k};
            count++;
            if (count % 1000000 == 0) {
                std::cout << "Loaded " << count << " points...\n";
            }
        } catch (...) {
            std::cerr << "Warning: Invalid line format: " << line << "\n";
        }
    }
    std::cout << "Loaded " << count << " points\n";
    return points;
}

// Subtract point using libsecp256k1
secp256k1_pubkey subtract_G_secp256k1(const secp256k1_pubkey& point) {
    secp256k1_pubkey result = point;
    cpp_int minus_one = mod(-1, n); // n - 1
    auto minus_one_bytes = cpp_int_to_bytes(minus_one);
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &result, minus_one_bytes.data())) {
        throw std::string("Failed to subtract G");
    }
    return result;
}

// Convert secp256k1_pubkey to Point
Point pubkey_to_point(const secp256k1_pubkey& pubkey) {
    unsigned char serialized[65];
    size_t serialized_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    std::string x_hex = bytes_to_hex(serialized + 1, 32);
    std::string y_hex = bytes_to_hex(serialized + 33, 32);
    return {cpp_int("0x" + x_hex), cpp_int("0x" + y_hex)};
}

// Search function for a thread (subtraction-based)
void search_subtraction(const Point& target, const secp256k1_pubkey& target_pubkey,
                        const std::unordered_map<std::string, std::pair<cpp_int, cpp_int>>& points,
                        cpp_int start_iter, cpp_int end_iter, cpp_int& found_key, cpp_int& iterations) {
    secp256k1_pubkey current_pubkey = target_pubkey;
    Point current = target;
    cpp_int counter = start_iter;

    // Fast-forward to start_iter
    for (cpp_int i = 0; i < start_iter && !found; ++i) {
        current_pubkey = subtract_G_secp256k1(current_pubkey);
        current = pubkey_to_point(current_pubkey);
    }

    while (counter < end_iter && !found) {
        auto it = points.find(current.x.str());
        if (it != points.end() && it->second.first == current.y) {
            std::lock_guard<std::mutex> lock(mtx);
            found_key = it->second.second; // Use k_point directly
            iterations = counter;
            found = true;
            std::cout << "Match found at iteration " << counter << "\n";
            return;
        }

        current_pubkey = subtract_G_secp256k1(current_pubkey);
        current = pubkey_to_point(current_pubkey);
        counter++;
        total_iterations++;
        if (counter % 1000000 == 0) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << "Thread at iteration " << counter << " (total: " << total_iterations << ")\n";
        }
    }
}

// Random search fallback
void search_random(const std::vector<unsigned char>& target_compressed, int thread_id, cpp_int& found_key, int max_attempts) {
    std::random_device rd;
    std::mt19937_64 rng(rd() + thread_id);

    unsigned char pubkey[33];
    size_t pubkey_len = 33;

    for (int i = 0; i < max_attempts && !found; ++i) {
        cpp_int k = generate_random_key(rng);
        auto privkey_bytes = cpp_int_to_bytes(k);

        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey_bytes.data())) {
            continue;
        }

        secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pub, SECP256K1_EC_COMPRESSED);

        bool match = true;
        for (size_t j = 0; j < 33; ++j) {
            if (pubkey[j] != target_compressed[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            std::lock_guard<std::mutex> lock(mtx);
            found_key = k;
            found = true;
            std::cout << "Match found in random search by thread " << thread_id << "\n";
            return;
        }

        if (i % 100000 == 0 && i > 0) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << "Random search thread " << thread_id << " checked " << i << " iterations...\n";
        }
    }
}

cpp_int parallel_search(const Point& target, const std::unordered_map<std::string, std::pair<cpp_int, cpp_int>>& points,
                        const std::vector<unsigned char>& target_compressed, int num_threads, cpp_int max_iter, int max_random_attempts) {
    std::vector<std::thread> threads;
    std::vector<cpp_int> found_keys(num_threads, 0);
    std::vector<cpp_int> iterations(num_threads, 0);

    std::cout << "Starting subtraction-based search with " << num_threads << " threads\n";
    std::cout << "Max iterations: " << max_iter << "\n";

    secp256k1_pubkey target_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &target_pubkey, target_compressed.data(), target_compressed.size())) {
        throw std::string("Failed to parse target public key");
    }

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; ++i) {
        cpp_int start_iter = i * (max_iter / num_threads);
        cpp_int end_iter = (i == num_threads - 1) ? max_iter : (i + 1) * (max_iter / num_threads);
        threads.emplace_back(search_subtraction, std::ref(target), std::ref(target_pubkey), std::ref(points),
                             start_iter, end_iter, std::ref(found_keys[i]), std::ref(iterations[i]));
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    for (size_t i = 0; i < num_threads; ++i) {
        if (found_keys[i] != 0) {
            std::cout << "\nFound private key in " << iterations[i] << " iterations (subtraction search)\n";
            std::cout << "Search completed in " << elapsed.count() << " seconds\n";
            return found_keys[i];
        }
    }

    std::cout << "\nNo match found after " << max_iter << " iterations (" << elapsed.count() << " seconds)\n";
    std::cout << "Falling back to random search...\n";

    threads.clear();
    found_keys.assign(num_threads, 0);
    total_iterations = 0;

    std::cout << "Starting random search with " << num_threads << " threads\n";
    std::cout << "Max attempts per thread: " << max_random_attempts << "\n";

    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(search_random, std::ref(target_compressed), i, std::ref(found_keys[i]), max_random_attempts);
    }

    for (auto& t : threads) {
        t.join();
    }

    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;

    for (size_t i = 0; i < num_threads; ++i) {
        if (found_keys[i] != 0) {
            std::cout << "\nFound private key in random search\n";
            std::cout << "Search completed in " << elapsed.count() << " seconds\n";
            return found_keys[i];
        }
    }

    std::cout << "\nNo match found after " << num_threads * max_random_attempts << " random attempts ("
              << elapsed.count() << " seconds)\n";
    return 0;
}

int main() {
    try {
        // Step 1: Generate random points
        int num_points = 10000000;
        generate_random_points(num_points);

        // Step 2: Load points
        auto points = load_points();

        // Step 3: Decompress target public key
        Point target = decompress_pubkey(target_compressed_pubkey);
        std::vector<unsigned char> target_compressed_bytes = hex_to_bytes(target_compressed_pubkey);
        std::cout << "Target public key:\nX: " << target.x << "\nY: " << target.y << "\n";

        // Step 4: Parallel search
        unsigned num_threads = std::thread::hardware_concurrency();
        cpp_int max_iter = 100000000;
        int max_random_attempts = 1000000;
        std::cout << "Using " << num_threads << " threads\n";

        auto start_time = std::chrono::high_resolution_clock::now();
        found = false;
        total_iterations = 0;
        cpp_int privkey = parallel_search(target, points, target_compressed_bytes, num_threads, max_iter, max_random_attempts);
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> search_elapsed = end_time - start_time;

        // Step 5: Verify private key
        std::string status = "NOT FOUND";
        if (privkey != 0) {
            auto privkey_bytes = cpp_int_to_bytes(privkey);
            secp256k1_pubkey pub;
            if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey_bytes.data())) {
                throw std::string("Failed to generate public key for verification");
            }
            unsigned char pubkey[33];
            size_t pubkey_len = 33;
            secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pub, SECP256K1_EC_COMPRESSED);
            bool match = true;
            for (size_t i = 0; i < 33; ++i) {
                if (pubkey[i] != target_compressed_bytes[i]) {
                    match = false;
                    break;
                }
            }
            status = match ? "VERIFIED" : "UNVERIFIED";
        }

        // Step 6: Save results
        std::ofstream out("results.txt");
        out << "Search Results:\n\n";
        out << "Public Key (compressed): " << target_compressed_pubkey << "\n";
        out << "Public Key (uncompressed):\nX: " << target.x << "\nY: " << target.y << "\n";
        out << "Private Key: " << (privkey != 0 ? privkey.str() : "None") << "\n";
        out << "Status: " << status << "\n";
        out << "Search time: " << search_elapsed.count() << " seconds\n";

        std::cout << "\nPrivate key: " << (privkey != 0 ? privkey.str() : "Not found") << "\n";
        std::cout << "Status: " << status << "\n";
        std::cout << "Search time: " << search_elapsed.count() << " seconds\n";

        secp256k1_context_destroy(ctx);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        secp256k1_context_destroy(ctx);
        return 1;
    } catch (const std::string& e) {
        std::cerr << "\nError: " << e << std::endl;
        secp256k1_context_destroy(ctx);
        return 1;
    }
}