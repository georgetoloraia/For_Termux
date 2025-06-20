#include <gmp.h>
#include <fstream>
#include <iostream>
#include <set>
#include <vector>
#include <random>
#include <thread>
#include <functional>
#include <secp256k1.h>
#include <iomanip>
#include <cstring>
#include <mutex>
#include <algorithm>

// g++ -o nand_gpt nand_gpt.cpp -lsecp256k1 -lgmp -pthread

// --- CONFIG ---
const std::string MODE = "random";  // "random" or "structured"
const int NUM_K = 8;
const std::string STRUCTURED_START = "340282366920938463463374607431768211456";  // 2^128
const int STRUCTURED_STEP = 1;
const std::string PUBS_FILE = "allpubs.txt";
const std::string MATCH_LOG = "matches_found.txt";
const int MAX_STEPS = 1410065408;

// --- Global EC Setup ---
secp256k1_context* ctx = nullptr;
secp256k1_pubkey G;
mpz_t order;
std::mutex log_mutex;

// --- String to mpz ---
void string_to_mpz(const std::string& str, mpz_t result) {
    mpz_set_str(result, str.c_str(), 10);
}

// --- mpz to 32-byte array (padded) ---
void mpz_to_bytes(mpz_t num, unsigned char* bytes) {
    memset(bytes, 0, 32);
    size_t count;
    unsigned char* temp = (unsigned char*)mpz_export(nullptr, &count, 1, 1, 1, 0, num);
    if (temp && count <= 32) {
        memcpy(bytes + (32 - count), temp, count);
        free(temp);
    }
}

// --- bytes to hex string ---
std::string bytes_to_hex(const unsigned char* bytes, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    return ss.str();
}

// --- lowercase string ---
std::string to_lowercase(const std::string& str) {
    std::string res = str;
    std::transform(res.begin(), res.end(), res.begin(), ::tolower);
    return res;
}

// --- Load known x values ---
std::set<std::string> load_allpubs_x(const std::string& path) {
    std::set<std::string> x_set;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << path << std::endl;
        return x_set;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find(',');
        if (pos != std::string::npos) {
            std::string x_str = line.substr(0, pos);
            mpz_t x;
            mpz_init_set_str(x, x_str.c_str(), 10);
            char* x_hex = mpz_get_str(nullptr, 16, x);
            x_set.insert(to_lowercase(x_hex));
            free(x_hex);
            mpz_clear(x);
        }
    }
    file.close();
    return x_set;
}

// --- NAND logic ---
void nand_256(mpz_t result, const mpz_t a, const mpz_t b) {
    mpz_t temp, mask;
    mpz_init(temp);
    mpz_init_set_str(mask, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
    mpz_and(temp, a, b);
    mpz_com(temp, temp);
    mpz_and(result, temp, mask);
    mpz_clear(temp);
    mpz_clear(mask);
}

// --- Worker thread ---
void process_k(const std::string& start_k_str, const std::set<std::string>& known_x) {
    std::set<std::string> visited;
    mpz_t k, new_k, qx, gx;
    secp256k1_pubkey Q, R;
    unsigned char Q_serialized[65], R_serialized[65];
    unsigned char k_bytes[32], new_k_bytes[32];
    size_t len = 65;

    mpz_init_set_str(k, start_k_str.c_str(), 10);
    mpz_init(new_k);
    mpz_init(qx);
    mpz_init(gx);

    secp256k1_ec_pubkey_serialize(ctx, Q_serialized, &len, &G, SECP256K1_EC_UNCOMPRESSED);
    mpz_set_str(gx, bytes_to_hex(Q_serialized + 1, 32).c_str(), 16);

    for (int step = 0; step < MAX_STEPS; ++step) {
        mpz_to_bytes(k, k_bytes);
        if (!secp256k1_ec_pubkey_create(ctx, &Q, k_bytes)) {
            std::cerr << "Invalid k at step " << step << std::endl;
            break;
        }

        secp256k1_ec_pubkey_serialize(ctx, Q_serialized, &len, &Q, SECP256K1_EC_UNCOMPRESSED);
        mpz_set_str(qx, bytes_to_hex(Q_serialized + 1, 32).c_str(), 16);

        nand_256(new_k, qx, gx);

        // --- Clamp new_k to valid private key range: 1 <= new_k < order ---
        if (mpz_cmp_ui(new_k, 0) <= 0 || mpz_cmp(new_k, order) >= 0) {
            continue; // invalid new_k, skip
        }

        mpz_to_bytes(new_k, new_k_bytes);
        if (!secp256k1_ec_pubkey_create(ctx, &R, new_k_bytes)) {
            std::cerr << "Invalid new_k at step " << step << std::endl;
            break;
        }

        secp256k1_ec_pubkey_serialize(ctx, R_serialized, &len, &R, SECP256K1_EC_UNCOMPRESSED);
        std::string rx_hex = to_lowercase(bytes_to_hex(R_serialized + 1, 32));

        if (known_x.find(rx_hex) != known_x.end()) {
            std::string match_line = "[MATCH] start_k=" + start_k_str + " step=" + std::to_string(step) +
                                     "\n  k=" + std::string(mpz_get_str(nullptr, 10, k)) +
                                     "\n  new_k=" + std::string(mpz_get_str(nullptr, 10, new_k)) +
                                     "\n  R.x=" + rx_hex;
            std::cout << match_line << std::endl;
            std::lock_guard<std::mutex> lock(log_mutex);
            std::ofstream log(MATCH_LOG, std::ios::app);
            log << match_line << "\n";
            break;
        }

        std::string k_str = mpz_get_str(nullptr, 10, new_k);
        if (mpz_cmp_ui(new_k, 0) == 0 || k_str == mpz_get_str(nullptr, 10, k) || visited.count(k_str)) {
            break;
        }

        visited.insert(mpz_get_str(nullptr, 10, k));
        mpz_set(k, new_k);
    }

    mpz_clears(k, new_k, qx, gx, nullptr);
}

// --- Generate k values ---
std::vector<std::string> generate_k_values(const std::string& mode, int num, const std::string& start, int step) {
    std::vector<std::string> k_values;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    std::random_device rd;
    gmp_randseed_ui(state, rd());

    if (mode == "random") {
        mpz_t max, temp;
        mpz_init(max);
        mpz_init(temp);
        mpz_sub_ui(max, order, 1);
        for (int i = 0; i < num; ++i) {
            mpz_urandomm(temp, state, max);
            k_values.emplace_back(mpz_get_str(nullptr, 10, temp));
        }
        mpz_clear(max);
        mpz_clear(temp);
    } else if (mode == "structured") {
        mpz_t base, temp;
        mpz_init_set_str(base, start.c_str(), 10);
        mpz_init(temp);
        for (int i = 0; i < num; ++i) {
            mpz_add_ui(temp, base, i * step);
            k_values.emplace_back(mpz_get_str(nullptr, 10, temp));
        }
        mpz_clear(base);
        mpz_clear(temp);
    }

    gmp_randclear(state);
    return k_values;
}

// --- Main ---
int main() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Parse generator G
    unsigned char G_bytes[65] = {
        0x04,
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
    };
    if (!secp256k1_ec_pubkey_parse(ctx, &G, G_bytes, 65)) {
        std::cerr << "Failed to parse generator point" << std::endl;
        return 1;
    }

    mpz_init_set_str(order, "115792089237316195423570985008687907852837564279074904382605163141518161494337", 10);

    // Load x-values
    auto known_x = load_allpubs_x(PUBS_FILE);
    std::remove(MATCH_LOG.c_str());

    std::cout << "[+] Generating " << NUM_K << " '" << MODE << "' k values..." << std::endl;
    auto k_list = generate_k_values(MODE, NUM_K, STRUCTURED_START, STRUCTURED_STEP);

    std::cout << "[+] Loaded " << known_x.size() << " known x-coordinates." << std::endl;
    std::cout << "[+] Starting threads...\n";

    unsigned int thread_limit = std::min<unsigned int>(std::thread::hardware_concurrency(), k_list.size());
    std::vector<std::thread> threads;

    for (const auto& k : k_list) {
        threads.emplace_back(process_k, k, std::ref(known_x));
        if (threads.size() >= thread_limit) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }
    for (auto& t : threads) t.join();

    secp256k1_context_destroy(ctx);
    mpz_clear(order);
    return 0;
}
