#ifndef KASMVNC_PKCE_HELPER_H
#define KASMVNC_PKCE_HELPER_H

#include <string>

namespace kasmvnc {
namespace oauth {

/**
 * PKCE (Proof Key for Code Exchange) Helper
 * Implements RFC 7636 for OAuth security
 */
class PKCEHelper {
public:
    /**
     * Generate a cryptographically random code verifier
     * Length: 43-128 characters (base64url encoded)
     * @return Random code verifier
     */
    static std::string generate_code_verifier();

    /**
     * Generate code challenge from verifier
     * Method S256: BASE64URL(SHA256(code_verifier))
     * Method plain: code_verifier (not recommended)
     * @param verifier Code verifier
     * @param method "S256" or "plain"
     * @return Code challenge
     */
    static std::string generate_code_challenge(
        const std::string& verifier,
        const std::string& method = "S256"
    );

    /**
     * Generate a cryptographically random state parameter
     * Used for CSRF protection
     * @return Random state string
     */
    static std::string generate_state();

private:
    /**
     * Generate random bytes
     * @param length Number of bytes
     * @return Random bytes as string
     */
    static std::string generate_random_bytes(size_t length);

    /**
     * Base64 URL-safe encode
     * @param data Data to encode
     * @return Base64url encoded string
     */
    static std::string base64url_encode(const std::string& data);

    /**
     * SHA-256 hash
     * @param data Data to hash
     * @return SHA-256 hash
     */
    static std::string sha256(const std::string& data);
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_PKCE_HELPER_H