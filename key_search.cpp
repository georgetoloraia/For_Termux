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
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <cstdlib>

// g++ -o key_search key_search.cpp -lcrypto -lcurl -pthread -std=c++11

// SECP256k1 curve order
const char* CURVE_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

std::mutex output_mutex;
std::mutex found_keys_mutex;

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
        if (line.empty() || line[0] == '#') continue; // Skip empty lines and comments

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
            } else {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "Set environment variable: " << key << std::endl;
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
    return size * nmemb; // Discard response
}

// Send Telegram message
void send_telegram_message(const std::string& message, const std::string& user_id) {
    // Debug: Print environment variables
    const char* bot_token = "";
    const char* chat_id = "";
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
        curl_easy_setopt(curl.curl, CURLOPT_TIMEOUT, 5L); // 5-second timeout

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

// Read x-coordinates from file
std::set<std::string> read_public_keys(const std::string& filename) {
    std::set<std::string> x_coords;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Failed to open " << filename << ". Exiting." << std::endl;
        return x_coords;
    }

    std::string line;
    while (std::getline(file, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) {
            // Validate hex string
            if (line.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
                // Convert to lowercase for consistency
                for (char& c : line) {
                    c = std::tolower(c);
                }
                x_coords.insert(line);
            }
        }
    }
    file.close();
    return x_coords;
}

// Generate random number string with specified digits
std::string generate_random_number(int min_digits, int max_digits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> digit_dist(0, 9);
    std::uniform_int_distribution<> length_dist(min_digits, max_digits);

    int num_digits = length_dist(gen);
    std::string number;
    number.reserve(num_digits);
    for (int i = 0; i < num_digits; ++i) {
        number += std::to_string(digit_dist(gen));
    }

    // Remove leading zeros
    number.erase(0, number.find_first_not_of('0'));
    return number.empty() ? "0" : number;
}

// Generate rotations of a number string
std::vector<std::string> generate_rotated_keys(const std::string& number) {
    std::vector<std::string> rotations;
    if (number == "0") return rotations;

    for (size_t i = 0; i < number.length(); ++i) {
        std::string rotated = number.substr(i) + number.substr(0, i);
        if (rotated[0] != '0') {
            rotations.push_back(rotated);
        }
    }
    return rotations;
}

// Generate public key from private key
bool generate_public_key(const std::string& priv_key_str, const EC_GROUP* group, BN_CTX* ctx, std::string& x_hex) {
    if (!group || !ctx) {
        return false;
    }

    BIGNUMWrapper priv_key;
    BIGNUMWrapper order;
    if (!BN_dec2bn(&priv_key.bn, priv_key_str.c_str()) || !BN_hex2bn(&order.bn, CURVE_ORDER_HEX)) {
        return false;
    }

    // Check if private key is valid
    if (BN_is_zero(priv_key.bn) || BN_cmp(priv_key.bn, order.bn) >= 0) {
        return false;
    }

    try {
        ECPointWrapper pub_key(group);
        if (!EC_POINT_mul(group, pub_key.point, priv_key.bn, nullptr, nullptr, ctx)) {
            return false;
        }

        BIGNUMWrapper x_bn;
        if (!EC_POINT_get_affine_coordinates(group, pub_key.point, x_bn.bn, nullptr, ctx)) {
            return false;
        }

        char* x_str = BN_bn2hex(x_bn.bn);
        if (!x_str) {
            return false;
        }
        x_hex = x_str;
        OPENSSL_free(x_str);

        // Convert to lowercase for consistency
        for (char& c : x_hex) {
            c = std::tolower(c);
        }
        return true;
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Error in generate_public_key: " << e.what() << std::endl;
        return false;
    }
}

// Worker function for each thread
void worker(std::set<std::string>& x_coords, int max_attempts, const std::string& user_id,
            int& found_count, bool& should_continue) {
    try {
        ECGroupWrapper group;
        BNCTXWrapper ctx;

        std::random_device rd;
        std::mt19937 gen(rd());

        for (int attempt = 0; attempt < max_attempts && should_continue; ++attempt) {
            std::string number = generate_random_number(4, 6); // Adjusted as per your code
            auto rotations = generate_rotated_keys(number);

            for (const auto& priv_key_str : rotations) {
                std::string x_hex;
                if (generate_public_key(priv_key_str, group.group, ctx.ctx, x_hex)) {
                    if (x_coords.find(x_hex) != x_coords.end()) {
                        std::string message = "Found key: " + priv_key_str + " -> x: " + x_hex;
                        {
                            std::lock_guard<std::mutex> lock(found_keys_mutex);
                            found_count++;
                            x_coords.erase(x_hex); // Remove found x-coordinate
                        }
                        {
                            std::lock_guard<std::mutex> out_lock(output_mutex);
                            std::cout << "User " << user_id << ": " << message << std::endl;
                        }
                        send_telegram_message(message, user_id);
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "Worker error: " << e.what() << std::endl;
    }
}

int main() {
    // Initialize CURL globally
    curl_global_init(CURL_GLOBAL_ALL);

    try {
        // Load .env file
        load_dotenv(".env");

        // Debug: Print environment variables
        {
            std::lock_guard<std::mutex> lock(output_mutex);
            const char* bot_token = std::getenv("TELEGRAM_BOT_TOKEN");
            const char* chat_id = std::getenv("TELEGRAM_CHAT_ID");
            std::cout << "Environment variables after load_dotenv: "
                      << "TELEGRAM_BOT_TOKEN=" << (bot_token ? bot_token : "unset")
                      << ", TELEGRAM_CHAT_ID=" << (chat_id ? chat_id : "unset") << std::endl;
        }

        std::string user_id;
        std::cout << "Enter user ID for logging (or press Enter for anonymous): ";
        std::getline(std::cin, user_id);
        if (user_id.empty()) user_id = "anonymous";

        const int max_attempts_per_thread = 10000;
        const int num_threads = std::thread::hardware_concurrency();
        int total_found_count = 0;

        // Read x-coordinates
        auto x_coords = read_public_keys("only_x.txt");
        if (x_coords.empty()) {
            std::cout << "No valid x-coordinates found in only_x.txt. Exiting." << std::endl;
            curl_global_cleanup();
            return 1;
        }

        bool continue_search = true;
        while (continue_search && !x_coords.empty()) {
            int found_count = 0;
            bool should_continue = true;

            std::cout << "Searching " << x_coords.size() << " x-coordinates with " << num_threads << " threads..." << std::endl;

            // Launch threads
            std::vector<std::thread> threads;
            for (int i = 0; i < num_threads; ++i) {
                threads.emplace_back(worker, std::ref(x_coords), max_attempts_per_thread / num_threads,
                                    std::ref(user_id), std::ref(found_count), std::ref(should_continue));
            }

            // Join threads
            for (auto& t : threads) {
                t.join();
            }

            total_found_count += found_count;

            // Results summary
            std::cout << "\nFound " << found_count << " keys in this round!" << std::endl;
            std::cout << "Total keys found: " << total_found_count << std::endl;
            std::cout << "Remaining x-coordinates: " << x_coords.size() << std::endl;

            if (!x_coords.empty()) {
                continue_search = true;
                // std::cout << "Continue searching with more attempts? (y/n): ";
                // std::string response;
                // std::getline(std::cin, response);
                // if (!response.empty() && (response[0] == 'y' || response[0] == 'Y')) {
                //     continue_search = true;
                // } else {
                //     continue_search = true;
                // }
            } else {
                continue_search = true;
            }
        }

        std::cout << "Search completed. Total keys found: " << total_found_count << std::endl;

        // Cleanup CURL
        curl_global_cleanup();
        return 0;
    } catch (const std::exception& e) {
        std::cout << "Main error: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }
}