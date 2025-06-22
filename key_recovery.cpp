#include <gmp.h>
#include <iostream>
#include <vector>
#include <thread>
#include <secp256k1.h>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <unordered_set>
#include <cstring>

// g++ -O3 -march=native -o key_recovery key_recovery.cpp -lsecp256k1 -lgmp -pthread

// ./key_recovery target_pub.txt 1 10000 1,2,3,4,5,6

// Secp256k1 curve constants
const char* CURVE_ORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337";

// Global context
secp256k1_context* ctx = nullptr;
std::mutex output_mutex;
std::atomic<uint64_t> keys_checked(0);
std::atomic<bool> key_found(false);
auto start_time = std::chrono::steady_clock::now();

struct PublicKey {
    mpz_t x;
    mpz_t y;
    std::string identifier;
};

// Enhanced mpz to bytes conversion
void mpz_to_bytes(mpz_t num, unsigned char* bytes) {
    size_t count;
    // First get count
    mpz_export(nullptr, &count, -1, 1, 1, 0, num);
    // Then export with padding
    memset(bytes, 0, 32);
    mpz_export(bytes + (32 - count), &count, -1, 1, 1, 0, num);
}

// Load multiple target public keys
std::vector<PublicKey> load_target_pubkeys(const std::string& path) {
    std::vector<PublicKey> pubkeys;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << path << std::endl;
        return pubkeys;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t comma1 = line.find(',');
        size_t comma2 = line.find(',', comma1 + 1);
        
        if (comma1 != std::string::npos && comma2 != std::string::npos) {
            PublicKey pub;
            mpz_init(pub.x);
            mpz_init(pub.y);
            
            std::string x_str = line.substr(0, comma1);
            std::string y_str = line.substr(comma1 + 1, comma2 - comma1 - 1);
            pub.identifier = line.substr(comma2 + 1);
            
            mpz_set_str(pub.x, x_str.c_str(), 10);
            mpz_set_str(pub.y, y_str.c_str(), 10);
            
            pubkeys.push_back(pub);
        }
    }
    
    file.close();
    return pubkeys;
}

// Enhanced public key matching
bool pubkey_matches(const secp256k1_pubkey* pubkey, const PublicKey& target) {
    unsigned char serialized[65];
    size_t len = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &len, pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        return false;
    }

    // mpz_t x, y;
    mpz_t x;
    mpz_init(x);
    // mpz_init(y);
    
    mpz_import(x, 32, -1, 1, 1, 0, serialized + 1);
    // mpz_import(y, 32, -1, 1, 1, 0, serialized + 33);
    
    // bool match = (mpz_cmp(x, target.x) == 0 && mpz_cmp(y, target.y) == 0);
    bool match = (mpz_cmp(x, target.x) == 0);

    mpz_clear(x);
    // mpz_clear(y);
    return match;
}

// Key transformation functions
uint64_t transform_key(uint64_t k, int transform_type) {
    switch (transform_type) {
        case 1: return k ^ 0xFFFFFFFFFFFFFFFF;  // Bit flip
        case 2: return k + 1;                   // Increment
        case 3: return k * 2;                   // Double
        case 4: return (k >> 1) | ((k & 1) << 63);  // Rotate right
        case 5: return k + (k >> 2);            // Add quarter value
        case 6: return (k << 1) ^ 0x5555555555555555;  // Shift and XOR
        default: return k;
    }
}

// Check a single key against all targets
void check_key(uint64_t k, const std::vector<PublicKey>& targets, 
               const std::vector<int>& transforms, mpz_t N) {
    unsigned char priv_bytes[32] = {0};
    secp256k1_pubkey generated_pub;
    
    // Try original key
    for (int t = -1; t < (int)transforms.size(); t++) {
        uint64_t current_k = k;
        if (t >= 0) {
            current_k = transform_key(k, transforms[t]);
            if (current_k == 0 || current_k >= mpz_get_ui(N)) continue;
        }
        
        // Convert to bytes
        for (int i = 0; i < 8; i++) {
            priv_bytes[31 - i] = (current_k >> (i * 8)) & 0xFF;
        }
        
        // Generate public key
        if (secp256k1_ec_pubkey_create(ctx, &generated_pub, priv_bytes)) {
            // Check against all targets
            for (const auto& target : targets) {
                if (pubkey_matches(&generated_pub, target)) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "\n\nFOUND PRIVATE KEY FOR " << target.identifier << ":\n";
                    std::cout << "Decimal: " << current_k << "\n";
                    std::cout << "Hex: 0x" << std::hex << current_k << std::dec << "\n";
                    std::cout << "Transform: " << (t == -1 ? "None" : std::to_string(transforms[t])) << "\n";
                    
                    // Save results
                    std::ofstream out("found_keys.txt", std::ios::app);
                    out << "Public Key: " << target.identifier << "\n";
                    out << "Private Key (dec): " << current_k << "\n";
                    out << "Private Key (hex): 0x" << std::hex << current_k << std::dec << "\n";
                    out << "Transform: " << (t == -1 ? "None" : std::to_string(transforms[t])) << "\n\n";
                    
                    key_found = true;
                    return;
                }
            }
        }
        
        keys_checked++;
    }
}

// Targeted search with patterns and transformations
void targeted_search(uint64_t start, uint64_t end, 
                    const std::vector<PublicKey>& targets,
                    const std::vector<int>& transforms,
                    mpz_t N) {
    // Common weak key patterns
    const std::vector<uint64_t> patterns = {
        0x0000000000000000, 0xFFFFFFFFFFFFFFFF, 
        0x5555555555555555, 0xAAAAAAAAAAAAAAAA,
        0x0123456789ABCDEF, 0xFEDCBA9876543210,
        0x00000000FFFFFFFF, 0xFFFFFFFF00000000
    };
    
    for (uint64_t base = start; base <= end && !key_found; base++) {
        // Check base key and simple transforms
        check_key(base, targets, transforms, N);
        
        // Check pattern variations
        for (uint64_t pattern : patterns) {
            if (key_found) break;
            
            check_key(base ^ pattern, targets, transforms, N);
            check_key(base + pattern, targets, transforms, N);
            check_key(base * pattern, targets, transforms, N);
        }
        
        // Save checkpoint every million keys
        if (base % 1000000 == 0) {
            std::lock_guard<std::mutex> lock(output_mutex);
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            double rate = keys_checked / static_cast<double>(elapsed);
            double progress = static_cast<double>(base - start) / (end - start) * 100.0;
            
            std::cout << "\r[CHECKPOINT] At key " << base << " (" 
                      << std::fixed << std::setprecision(2) << progress << "%) "
                      << "Rate: " << static_cast<int>(rate) << " keys/sec"
                      << std::flush;
        }
    }
}

// Progress display with ETA
void show_progress(uint64_t max_keys) {
    uint64_t last_count = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!key_found && keys_checked < max_keys) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        if (elapsed > 0) {
            uint64_t current_count = keys_checked.load();
            double rate = (current_count - last_count) / 
                         std::chrono::duration<double>(now - last_time).count();
            last_count = current_count;
            last_time = now;
            
            double progress = static_cast<double>(current_count) / max_keys * 100.0;
            uint64_t remaining = static_cast<uint64_t>((max_keys - current_count) / rate);
            
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "\rProgress: " << std::fixed << std::setprecision(2) << progress << "%"
                      << " | Keys/sec: " << static_cast<int>(rate)
                      << " | ETA: " << remaining << "s "
                      << " | Checked: " << current_count << "/" << max_keys
                      << std::flush;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Enhanced Private Key Recovery\n";
        std::cerr << "Usage: " << argv[0] << " <pubkey_file> <start> <end> [transforms]\n";
        std::cerr << "Example: " << argv[0] << " targets.txt 1 1000000 1,2,3\n";
        std::cerr << "Transforms: 1=bitflip, 2=increment, 3=double, 4=rotate, 5=add_quarter, 6=shift_xor\n";
        return 1;
    }
    
    // Parse arguments
    std::string pubkey_file = argv[1];
    uint64_t start_range = std::stoull(argv[2]);
    uint64_t end_range = std::stoull(argv[3]);
    
    // Parse transforms
    std::vector<int> transforms;
    if (argc > 4) {
        std::string transform_str = argv[4];
        size_t pos = 0;
        while ((pos = transform_str.find(',')) != std::string::npos) {
            transforms.push_back(std::stoi(transform_str.substr(0, pos)));
            transform_str.erase(0, pos + 1);
        }
        transforms.push_back(std::stoi(transform_str));
    }
    
    // Initialize secp256k1
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    start_time = std::chrono::steady_clock::now();
    
    // Initialize curve order
    mpz_t N;
    mpz_init_set_str(N, CURVE_ORDER, 10);
    
    // Load targets
    auto targets = load_target_pubkeys(pubkey_file);
    if (targets.empty()) {
        std::cerr << "No valid target public keys loaded\n";
        return 1;
    }
    
    std::cout << "Loaded " << targets.size() << " target public keys\n";
    std::cout << "Searching range " << start_range << " to " << end_range << "\n";
    if (!transforms.empty()) {
        std::cout << "Using transforms: ";
        for (int t : transforms) std::cout << t << " ";
        std::cout << "\n";
    }
    std::cout << "Using weak key patterns\n";
    
    // Calculate total work
    uint64_t total_keys = (end_range - start_range + 1) * (1 + transforms.size()) * 19; // 19 = 1 base + 6 patterns × 3 ops
    
    // Thread configuration
    const unsigned NUM_THREADS = std::max(1u, std::thread::hardware_concurrency());
    const uint64_t keys_per_thread = (end_range - start_range + 1) / NUM_THREADS;
    
    std::cout << "Using " << NUM_THREADS << " threads\n\n";
    
    // Start progress thread
    std::thread progress_thread(show_progress, total_keys);
    
    // Start worker threads
    std::vector<std::thread> worker_threads;
    for (unsigned t = 0; t < NUM_THREADS; t++) {
        uint64_t start = start_range + t * keys_per_thread;
        uint64_t end = (t == NUM_THREADS - 1) ? end_range : start + keys_per_thread - 1;
        
        worker_threads.emplace_back(targeted_search, start, end, 
                                  std::ref(targets), std::ref(transforms), N);
    }
    
    // Wait for workers
    for (auto& t : worker_threads) {
        t.join();
    }
    
    // Finalize progress
    if (progress_thread.joinable()) {
        progress_thread.join();
    }
    
    // Results summary
    auto end_time = std::chrono::steady_clock::now();
    auto total_sec = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    double rate = (total_sec > 0) ? keys_checked / static_cast<double>(total_sec) : 0;
    
    std::cout << "\n\nSearch completed in " << total_sec << " seconds ("
              << static_cast<int>(rate) << " keys/sec)\n";
    
    if (!key_found) {
        std::cout << "No matching private keys found in the specified range.\n";
        std::cout << "Suggestions:\n";
        std::cout << "1. Try a larger range (e.g., 1 to 1000000000)\n";
        std::cout << "2. Add more transformations (e.g., 1,2,3,4,5,6)\n";
        std::cout << "3. Focus on known vulnerable ranges\n";
    }
    
    // Cleanup
    for (auto& target : targets) {
        mpz_clear(target.x);
        mpz_clear(target.y);
    }
    mpz_clear(N);
    secp256k1_context_destroy(ctx);
    
    return 0;
}