#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <random>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <cstdlib>
#include <csignal>

// g++ -o key_search7 key_search7.cpp -lcrypto -lcurl -pthread -std=c++11

// SECP256k1 curve order
const char* CURVE_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
// SECP256k1 field size (prime p)
const char* FIELD_SIZE_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

std::mutex output_mutex;
std::mutex found_keys_mutex;
std::mutex continue_mutex;
volatile sig_atomic_t interrupted = 0;

// Signal handler for Ctrl+C
void signal_handler(int signal) {
    if (signal == SIGINT) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "\nReceived Ctrl+C. Exiting gracefully..." << std::endl;
        interrupted = 1;
    }
}

// RAII wrapper for OpenSSL BIGNUM
class BIGNUMWrapper {
public:
    BIGNUM* bn;
    BIGNUMWrapper() : bn(BN_new()) {
        if (!bn) throw std::runtime_error("Failed to initialize BIGNUM");
    }
    ~BIGNUMWrapper() { if (bn) BN_free(bn); }
    BIGNUMWrapper(const BIGNUMWrapper&) = delete;
    BIGNUMWrapper& operator=(const BIGNUMWrapper&) = delete;
};

// RAII wrapper for OpenSSL EC_POINT
class ECPointWrapper {
public:
    EC_POINT* point;
    explicit ECPointWrapper(const EC_GROUP* group) : point(EC_POINT_new(group)) {
        if (!point) throw std::runtime_error("Failed to initialize EC_POINT");
    }
    ~ECPointWrapper() { if (point) EC_POINT_free(point); }
    ECPointWrapper(const ECPointWrapper&) = delete;
    ECPointWrapper& operator=(const ECPointWrapper&) = delete;
};

// RAII wrapper for OpenSSL EC_GROUP
class ECGroupWrapper {
public:
    EC_GROUP* group;
    ECGroupWrapper() : group(EC_GROUP_new_by_curve_name(NID_secp256k1)) {
        if (!group) throw std::runtime_error("Failed to initialize SECP256k1 group");
    }
    ~ECGroupWrapper() { if (group) EC_GROUP_free(group); }
    ECGroupWrapper(const ECGroupWrapper&) = delete;
    ECGroupWrapper& operator=(const ECGroupWrapper&) = delete;
};

// RAII wrapper for OpenSSL BN_CTX
class BNCTXWrapper {
public:
    BN_CTX* ctx;
    BNCTXWrapper() : ctx(BN_CTX_new()) {
        if (!ctx) throw std::runtime_error("Failed to initialize BN_CTX");
    }
    ~BNCTXWrapper() { if (ctx) BN_CTX_free(ctx); }
    BNCTXWrapper(const BNCTXWrapper&) = delete;
    BNCTXWrapper& operator=(const BNCTXWrapper&) = delete;
};

// RAII wrapper for CURL
class CURLWrapper {
public:
    CURL* curl;
    CURLWrapper() : curl(curl_easy_init()) {
        if (!curl) throw std::runtime_error("Failed to initialize CURL");
    }
    ~CURLWrapper() { if (curl) curl_easy_cleanup(curl); }
    CURLWrapper(const CURLWrapper&) = delete;
    CURLWrapper& operator=(const CURLWrapper&) = delete;
};

// Read public keys from file (accepts decimal x,y coordinates)
std::vector<std::pair<std::string, std::string>> read_public_keys(const std::string& filename) {
    std::vector<std::pair<std::string, std::string>> keys;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Failed to open " << filename << ". Exiting." << std::endl;
        return keys;
    }

    ECGroupWrapper group;
    BNCTXWrapper ctx;
    std::string line;
    size_t valid_keys = 0;
    while (std::getline(file, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        size_t pos = line.find(',');
        if (pos != std::string::npos) {
            std::string x_dec = line.substr(0, pos);
            std::string y_dec = line.substr(pos + 1);
            if (!x_dec.empty() && !y_dec.empty() &&
                x_dec.find_first_not_of("0123456789") == std::string::npos &&
                y_dec.find_first_not_of("0123456789") == std::string::npos) {
                BIGNUMWrapper x_bn;
                BIGNUMWrapper y_bn;
                if (!BN_dec2bn(&x_bn.bn, x_dec.c_str()) || !BN_dec2bn(&y_bn.bn, y_dec.c_str())) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "Skipping invalid line (BN_dec2bn failed): " << line << std::endl;
                    continue;
                }
                BIGNUMWrapper order;
                BIGNUMWrapper field_size;
                if (!BN_hex2bn(&order.bn, CURVE_ORDER_HEX) || !BN_hex2bn(&field_size.bn, FIELD_SIZE_HEX)) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "Failed to initialize curve order or field size" << std::endl;
                    continue;
                }
                if (BN_is_zero(x_bn.bn) || BN_cmp(x_bn.bn, field_size.bn) >= 0 ||
                    BN_is_zero(y_bn.bn) || BN_cmp(y_bn.bn, field_size.bn) >= 0) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "Skipping invalid line (out of field range): " << line << std::endl;
                    continue;
                }
                ECPointWrapper point(group.group);
                if (!EC_POINT_set_affine_coordinates(group.group, point.point, x_bn.bn, y_bn.bn, ctx.ctx)) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "Skipping invalid line (not on curve): " << line << std::endl;
                    continue;
                }
                char* x_hex = BN_bn2hex(x_bn.bn);
                char* y_hex = BN_bn2hex(y_bn.bn);
                if (!x_hex || !y_hex) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "Skipping invalid line (BN_bn2hex failed): " << line << std::endl;
                    OPENSSL_free(x_hex);
                    OPENSSL_free(y_hex);
                    continue;
                }
                std::string x_str = x_hex;
                std::string y_str = y_hex;
                OPENSSL_free(x_hex);
                OPENSSL_free(y_hex);
                x_str = std::string(64 - x_str.length(), '0') + x_str;
                y_str = std::string(64 - y_str.length(), '0') + y_str;
                for (char& c : x_str) c = std::tolower(c);
                for (char& c : y_str) c = std::tolower(c);
                keys.push_back({x_str, y_str});
                valid_keys++;
            } else {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "Skipping invalid line (non-decimal): " << line << std::endl;
            }
        }
    }
    file.close();
    std::lock_guard<std::mutex> lock(output_mutex);
    std::cout << "Loaded " << valid_keys << " valid public keys from " << filename << std::endl;
    return keys;
}

// Read x-coordinates from only_x.txt
std::set<std::string> read_only_x(const std::string& filename) {
    std::set<std::string> x_coords;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Failed to open " << filename << ". Continuing without x-coordinates." << std::endl;
        return x_coords;
    }

    BIGNUMWrapper field_size;
    if (!BN_hex2bn(&field_size.bn, FIELD_SIZE_HEX)) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Failed to initialize field size" << std::endl;
        return x_coords;
    }

    std::string line;
    size_t valid_coords = 0;
    while (std::getline(file, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (!line.empty() && (line.size() == 63 || line.size() == 64) &&
            line.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
            // Pad 63-char lines with leading zero
            if (line.size() == 63) {
                line = "0" + line;
            }
            // Convert to lowercase
            for (char& c : line) c = std::tolower(c);
            // Validate against field size
            BIGNUMWrapper x_bn;
            if (!BN_hex2bn(&x_bn.bn, line.c_str())) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "Skipping invalid x-coordinate (BN_hex2bn failed): " << line << std::endl;
                continue;
            }
            if (BN_is_zero(x_bn.bn) || BN_cmp(x_bn.bn, field_size.bn) >= 0) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "Skipping invalid x-coordinate (out of field range): " << line << std::endl;
                continue;
            }
            x_coords.insert(line);
            valid_coords++;
        } else {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "Skipping invalid x-coordinate: " << line << std::endl;
        }
    }
    file.close();
    std::lock_guard<std::mutex> lock(output_mutex);
    std::cout << "Loaded " << valid_coords << " valid x-coordinates from " << filename << std::endl;
    return x_coords;
}

// Load environment variables from .env file
bool load_dotenv(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Failed to open " << filename << ". Using existing environment variables." << std::endl;
        return false;
    }

    std::string line;
    bool found_token = false, found_chat_id = false;
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') continue;

        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));

        if (!key.empty() && !value.empty()) {
            if (key == "TELEGRAM_BOT_TOKEN") found_token = true;
            if (key == "TELEGRAM_CHAT_ID") found_chat_id = true;
            if (setenv(key.c_str(), value.c_str(), 1) != 0) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "Failed to set environment variable: " << key << std::endl;
            }
        }
    }
    file.close();
    if (!found_token || !found_chat_id) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Warning: .env missing "
                  << (!found_token ? "TELEGRAM_BOT_TOKEN" : "")
                  << (!found_token && !found_chat_id ? " and " : "")
                  << (!found_chat_id ? "TELEGRAM_CHAT_ID" : "") << std::endl;
        return false;
    }
    return true;
}

// Callback function for CURL to discard response
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    return size * nmemb;
}

// Send Telegram message
void send_telegram_message(const std::string& message, const std::string& user_id) {
    const char* bot_token = getenv("TELEGRAM_BOT_TOKEN");
    const char* chat_id = getenv("TELEGRAM_CHAT_ID");
    if (!bot_token || !chat_id) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Telegram notification skipped: TELEGRAM_BOT_TOKEN=" << (bot_token ? bot_token : "unset")
                  << ", TELEGRAM_CHAT_ID=" << (chat_id ? chat_id : "unset") << std::endl;
        return;
    }

    try {
        CURLWrapper curl;
        std::string url = "https://api.telegram.org/bot" + std::string(bot_token) + "/sendMessage";
        std::string post_data = "chat_id=" + std::string(chat_id) + "&text=User " + user_id + ": " + message;

        curl_easy_setopt(curl.curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl.curl, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl.curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl.curl, CURLOPT_TIMEOUT, 5L);

        CURLcode res = curl_easy_perform(curl.curl);
        if (res != CURLE_OK) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "Telegram notification failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "Telegram notification sent successfully" << std::endl;
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Telegram notification error: " << e.what() << std::endl;
    }
}

// Generate public key from private key (unchanged)
bool generate_public_key(const std::string& priv_key_str, const EC_GROUP* group, BN_CTX* ctx, std::string& x_hex) {
    if (!group || !ctx) {
        return false;
    }

    BIGNUMWrapper priv_key;
    BIGNUMWrapper order;
    if (!BN_hex2bn(&priv_key.bn, priv_key_str.c_str()) || !BN_hex2bn(&order.bn, CURVE_ORDER_HEX)) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "BN_hex2bn failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }

    if (BN_is_zero(priv_key.bn) || BN_cmp(priv_key.bn, order.bn) >= 0) {
        return false;
    }

    try {
        ECPointWrapper pub_key(group);
        if (!EC_POINT_mul(group, pub_key.point, priv_key.bn, nullptr, nullptr, ctx)) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "EC_POINT_mul failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            return false;
        }

        BIGNUMWrapper x_bn;
        if (!EC_POINT_get_affine_coordinates(group, pub_key.point, x_bn.bn, nullptr, ctx)) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "EC_POINT_get_affine_coordinates failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            return false;
        }

        char* x_str = BN_bn2hex(x_bn.bn);
        if (!x_str) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "BN_bn2hex failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            return false;
        }
        x_hex = x_str;
        OPENSSL_free(x_str);

        for (char& c : x_hex) c = std::tolower(c);
        return true;
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Error in generate_public_key: " << e.what() << std::endl;
        return false;
    }
}

// Worker thread function with modular difference logic
void worker(const std::vector<std::pair<std::string, std::string>>& public_keys,
            size_t start_idx, size_t end_idx,
            const std::set<std::string>& x_coords,
            const std::string& user_id, int& found_count, bool& should_continue,
            size_t& total_tests) {
    try {
        ECGroupWrapper group;
        BNCTXWrapper ctx;
        BIGNUMWrapper curve_order;
        if (!BN_hex2bn(&curve_order.bn, CURVE_ORDER_HEX)) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "Failed to initialize curve order" << std::endl;
            return;
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(-10, 10);

        for (size_t i = start_idx; i < end_idx; i++) {
            if (!([&] { std::lock_guard<std::mutex> lock(continue_mutex); return should_continue && !interrupted; }())) break;
            BIGNUMWrapper x1_bn;
            if (!BN_hex2bn(&x1_bn.bn, public_keys[i].first.c_str())) continue;
            for (size_t j = 0; j < public_keys.size() && j != i; j++) {
                if (!([&] { std::lock_guard<std::mutex> lock(continue_mutex); return should_continue && !interrupted; }())) break;
                BIGNUMWrapper x2_bn;
                if (!BN_hex2bn(&x2_bn.bn, public_keys[j].first.c_str())) continue;
                BIGNUMWrapper diff;
                if (BN_sub(diff.bn, x1_bn.bn, x2_bn.bn) &&
                    BN_nnmod(diff.bn, diff.bn, curve_order.bn, ctx.ctx)) {
                    int offset = dis(gen); // Random offset between -10 and 10
                    if (offset != 0) {
                        BIGNUMWrapper offset_bn;
                        BN_set_word(offset_bn.bn, abs(offset));
                        if (offset < 0) BN_sub(diff.bn, diff.bn, offset_bn.bn);
                        else BN_add(diff.bn, diff.bn, offset_bn.bn);
                        BN_nnmod(diff.bn, diff.bn, curve_order.bn, ctx.ctx);
                    }
                    char* priv_key_str = BN_bn2hex(diff.bn);
                    if (priv_key_str) {
                        std::string computed_x;
                        if (generate_public_key(priv_key_str, group.group, ctx.ctx, computed_x)) {
                            {
                                std::lock_guard<std::mutex> lock(output_mutex);
                                total_tests++;
                            }
                            if (x_coords.find(computed_x) != x_coords.end()) {
                                std::string message = "Found key: " + std::string(priv_key_str) + " (offset " + std::to_string(offset) + ") -> x: " + computed_x;
                                {
                                    std::lock_guard<std::mutex> lock(found_keys_mutex);
                                    found_count++;
                                }
                                {
                                    std::lock_guard<std::mutex> lock(output_mutex);
                                    std::cout << "User " << user_id << ": " << message << std::endl;
                                }
                                send_telegram_message(message, user_id);
                                {
                                    std::lock_guard<std::mutex> lock(continue_mutex);
                                    should_continue = false;
                                }
                            }
                        }
                        OPENSSL_free(priv_key_str);
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Worker error: " << e.what() << std::endl;
    }
}

void test_key_matching() {
    ECGroupWrapper group;
    BNCTXWrapper ctx;
    BIGNUMWrapper priv_key;
    BN_hex2bn(&priv_key.bn, "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
    std::string computed_x;
    if (generate_public_key("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725", group.group, ctx.ctx, computed_x)) {
        std::cout << "Test: Computed x = " << computed_x << std::endl;
        // Add the expected x to x_coords for testing
        std::set<std::string> x_coords = {"50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"};
        if (x_coords.find(computed_x) != x_coords.end()) {
            std::cout << "Test: Match found! Key matching works." << std::endl;
        } else {
            std::cout << "Test: No match. Check x-coordinate computation." << std::endl;
        }
    }
}

// Main function
int main() {
    test_key_matching();

    std::signal(SIGINT, signal_handler);

    curl_global_init(CURL_GLOBAL_ALL);
    load_dotenv(".env");

    std::string user_id;
    std::cout << "Enter user ID: ";
    std::getline(std::cin, user_id);
    if (user_id.empty()) user_id = "anonymous";

    auto public_keys = read_public_keys("allpubs.txt");
    if (public_keys.empty()) {
        std::cout << "No valid public keys found in allpubs.txt. Exiting." << std::endl;
        curl_global_cleanup();
        return 1;
    }

    auto x_coords = read_only_x("only_x.txt");

    int num_threads = std::thread::hardware_concurrency();
    size_t total_tests = 0;
    int iteration = 0;

    while (!interrupted) {
        int found_count = 0;
        bool should_continue = true;
        total_tests = 0;

        std::vector<std::thread> threads;
        size_t keys_per_thread = public_keys.size() / num_threads;
        for (int i = 0; i < num_threads; i++) {
            size_t start_idx = i * keys_per_thread;
            size_t end_idx = (i == num_threads - 1) ? public_keys.size() : (i + 1) * keys_per_thread;
            threads.emplace_back([&, start_idx, end_idx]() {
                worker(public_keys, start_idx, end_idx, x_coords, user_id, found_count, should_continue, total_tests);
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        std::cout << "Iteration " << ++iteration << ": Found " << found_count << " keys total!" << std::endl;
        std::cout << "Tested " << total_tests << " candidates." << std::endl;

        if (found_count > 0) break;
    }

    if (interrupted) {
        std::cout << "Search interrupted by user." << std::endl;
    }

    curl_global_cleanup();
    return 0;
}