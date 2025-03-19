#include <vector>
#include <sstream> //for std::ostringstream
#include <iomanip> //for std::setw, std::hex, and std::setfill
#include <openssl/evp.h> //for all other OpenSSL function calls
#include <openssl/sha.h> //for SHA512_DIGEST_LENGTH

#ifndef SHA3_512_HPP
#define SHA3_512_HPP
std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
std::string sha3_512(const std::string& input);
#endif
