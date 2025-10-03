#include "pkce_helper.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

namespace kasmvnc {
namespace oauth {

std::string PKCEHelper::generate_code_verifier() {
    // Generate 43-128 bytes of random data
    // 43 bytes = minimum for PKCE spec
    // Using 64 bytes for good security margin
    constexpr size_t verifier_length = 64;
    std::string random_bytes = generate_random_bytes(verifier_length);

    // Base64url encode (no padding)
    return base64url_encode(random_bytes);
}

std::string PKCEHelper::generate_code_challenge(
    const std::string& verifier,
    const std::string& method
) {
    if (method == "S256") {
        // SHA-256 hash of verifier
        std::string hash = sha256(verifier);
        // Base64url encode the hash
        return base64url_encode(hash);
    } else if (method == "plain") {
        // Plain method: challenge = verifier (not recommended)
        return verifier;
    } else {
        throw std::invalid_argument("Invalid PKCE method: " + method);
    }
}

std::string PKCEHelper::generate_state() {
    // Generate 32 bytes of random data for state
    constexpr size_t state_length = 32;
    std::string random_bytes = generate_random_bytes(state_length);
    return base64url_encode(random_bytes);
}

std::string PKCEHelper::generate_random_bytes(size_t length) {
    std::vector<unsigned char> buffer(length);

    // Use OpenSSL's cryptographically secure random generator
    if (RAND_bytes(buffer.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }

    return std::string(buffer.begin(), buffer.end());
}

std::string PKCEHelper::base64url_encode(const std::string& data) {
    // Standard Base64 encoding
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.length());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    // Convert to Base64url: replace + with -, / with _, remove padding =
    for (char& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    // Remove padding
    size_t pad_pos = result.find('=');
    if (pad_pos != std::string::npos) {
        result = result.substr(0, pad_pos);
    }

    return result;
}

std::string PKCEHelper::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.c_str(), data.length());
    SHA256_Final(hash, &sha256_ctx);

    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

} // namespace oauth
} // namespace kasmvnc