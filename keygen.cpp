#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <secp256k1.h>
#include <iomanip>

// g++ -std=c++17 -o keygen keygen.cpp -lsecp256k1 -pthread

const int THREADS = 8;
const uint64_t LOOP_PER_THREAD = 2'000'000;

std::unordered_set<std::string> known_pubs;
std::mutex file_mutex;
std::atomic<bool> found(false);

// Convert bytes to hex
std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

// Load compressed pubkeys from file
std::unordered_set<std::string> load_known_pubkeys(const std::string& filename) {
    std::unordered_set<std::string> pubkeys;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[!] Error: Could not open " << filename << "\n";
        return pubkeys;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) pubkeys.insert(line);
    }
    file.close();
    return pubkeys;
}

// Compare two 32-byte arrays (returns -1 if a < b, 0 if a == b, 1 if a > b)
int compare_32bytes(const unsigned char* a, const unsigned char* b) {
    for (int i = 0; i < 32; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Generate random 256-bit private key in range [min, max]
void fill_random_scalar(unsigned char* scalar, std::mt19937_64& gen) {
    // Define range bounds as 32-byte arrays
    const unsigned char min[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
    };
    const unsigned char max[32] = {
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    // Generate random 32-byte scalar
    do {
        for (int i = 0; i < 32; ++i) {
            scalar[i] = static_cast<unsigned char>(std::uniform_int_distribution<uint32_t>(0, 255)(gen));
        }
        // Ensure scalar is in range [min, max]
    } while (compare_32bytes(scalar, min) < 0 || compare_32bytes(scalar, max) > 0);
}

void worker(int tid, secp256k1_context* ctx) {
    std::mt19937_64 gen(std::random_device{}());

    for (uint64_t i = 0; i < LOOP_PER_THREAD && !found.load(); ++i) {
        unsigned char priv[32];
        fill_random_scalar(priv, gen);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
            continue; // Invalid scalar, retry
        }

        unsigned char compressed[33];
        size_t outlen = 33;
        secp256k1_ec_pubkey_serialize(ctx, compressed, &outlen, &pubkey, SECP256K1_EC_COMPRESSED);
        std::string hex_comp = bytes_to_hex(compressed, 33);

        if (known_pubs.find(hex_comp) != known_pubs.end()) {
            std::lock_guard<std::mutex> lock(file_mutex);
            if (!found.exchange(true)) {
                std::cout << "\n[✓] Match found on thread " << tid << "\n";
                std::cout << "[+] Compressed Pubkey: " << hex_comp << "\n";
                std::cout << "[+] Private Key: 0x" << bytes_to_hex(priv, 32) << "\n";

                std::ofstream f("found_keys.txt", std::ios::app);
                if (f.is_open()) {
                    f << "Match: " << hex_comp << "\nPrivateKey = 0x" << bytes_to_hex(priv, 32) << "\n\n";
                    f.close();
                } else {
                    std::cerr << "[!] Error: Could not open found_keys.txt for writing\n";
                }
            }
            return;
        }

        if (i % 100000 == 0 && tid == 0) {
            std::cout << "[Thread " << tid << "] Checked " << i << " keys...\n";
        }
    }
}

int main() {
    std::cout << "[+] Loading known pubkeys from pubs.txt...\n";
    known_pubs = load_known_pubkeys("pubs.txt");
    if (known_pubs.empty()) {
        std::cerr << "[!] Warning: No public keys loaded from pubs.txt\n";
    } else {
        std::cout << "[+] Loaded " << known_pubs.size() << " public keys\n";
    }

    std::cout << "[+] Starting " << THREADS << " threads...\n";

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        std::cerr << "[!] Error: Failed to create secp256k1 context\n";
        return 1;
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < THREADS; ++i) {
        threads.emplace_back(worker, i, ctx);
    }

    for (auto& t : threads) {
        t.join();
    }

    secp256k1_context_destroy(ctx);
    std::cout << "[✓] Done.\n";
    return 0;
}