#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring> // Added for memset
#include <secp256k1.h>
#include <iomanip>

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
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) pubkeys.insert(line);
    }
    return pubkeys;
}

// Generate random 256-bit number in range [1, n-1] for secp256k1
void fill_random_scalar(unsigned char* scalar, std::mt19937_64& gen) {
    // secp256k1 curve order (n)
    const unsigned char curve_order[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };

    // Generate random 32-byte scalar
    for (int i = 0; i < 32; ++i) {
        scalar[i] = static_cast<unsigned char>(std::uniform_int_distribution<uint32_t>(0, 255)(gen));
    }

    // Ensure scalar is in range [1, n-1]
    // Compare with curve order and adjust if necessary
    bool is_zero = true;
    bool too_large = false;
    for (int i = 0; i < 32; ++i) {
        if (scalar[i] > curve_order[i]) {
            too_large = true;
            break;
        } else if (scalar[i] < curve_order[i]) {
            is_zero = false;
            break;
        }
    }

    // If scalar is zero or >= n, regenerate
    if (is_zero || too_large) {
        fill_random_scalar(scalar, gen); // Recursive call to regenerate
    }
}

void worker(int tid, secp256k1_context* ctx) {
    std::mt19937_64 gen(std::random_device{}());

    for (uint64_t i = 0; i < LOOP_PER_THREAD && !found.load(); ++i) {
        unsigned char priv[32];
        fill_random_scalar(priv, gen);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv)) {
            continue; // invalid scalar, retry
        }

        unsigned char compressed[33];
        size_t outlen = 33;
        secp256k1_ec_pubkey_serialize(ctx, compressed, &outlen, &pubkey, SECP256K1_EC_COMPRESSED);
        std::string hex_comp = bytes_to_hex(compressed, 33);

        if (known_pubs.find(hex_comp) != known_pubs.end()) {
            std::lock_guard<std::mutex> lock(file_mutex);
            if (!found.exchange(true)) {
                std::cout << "\n[✓] Match found on thread " << tid << "\n";
                std::cout << "[+] Compressed: " << hex_comp << "\n";

                std::ofstream f("found_keys.txt", std::ios::app);
                f << "Match: " << hex_comp << "\nPrivateKey = 0x" << bytes_to_hex(priv, 32) << "\n";
                f.close();
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

    std::cout << "[+] Starting " << THREADS << " threads...\n";

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

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