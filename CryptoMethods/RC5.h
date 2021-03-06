#pragma once
#include "CryptoMethodDefines.h"

namespace CryptoMethods {

#define RC5_WORD_W 32
#if RC5_WORD_W == 32
typedef uint32_t rc5_word;

constexpr rc5_word c_rc5Pw = 0xb7e15163u;
constexpr rc5_word c_rc5Qw = 0x9e3779b9u;

#elif RC5_WORD_W == 64
typedef uint64_t rc5_word;

constexpr rc5_word c_rc5Pw = 0xb7e151628aed2a6bull;
constexpr rc5_word c_rc5Qw = 0x9e3779b97f4a7c15ull;

#endif

constexpr size_t c_rc5w = RC5_WORD_W;  // length of a word in bits
constexpr size_t c_rc5r = 12;          // rounds to encrypt data
constexpr size_t c_rc5b = 16;          // length of the key in bytes

constexpr size_t c_rc5u = c_rc5w / 8;        // length of a word in bytes
constexpr size_t c_rc5t = 2 * (c_rc5r + 1);  // number of round subkeys
constexpr size_t c_rc5c = (1 < 8 * c_rc5b / c_rc5w)
    ? (8 * c_rc5b / c_rc5w)
    : 1;  // length of the key in words

class RC5 : public CipherBase {
public:
    RC5();
    virtual ~RC5();

    virtual const enum_crypt_methods CryptMethod() override { return p_method; }
    virtual const size_t BlockSize() override;
    virtual const size_t KeyLength(size_t *min, size_t *max) override;

    virtual bool SetKey(const uint8_t *key, const size_t keylen) override;
    virtual bool Encrypt(const uint8_t *plain, uint8_t *cipher) override;
    virtual bool Decrypt(const uint8_t *cipher, uint8_t *plain) override;

private:
    enum_crypt_methods p_method;
    size_t p_blocksize;

    bool p_haskey;

    uint8_t p_key[c_rc5b];

    rc5_word p_roundkey[c_rc5t];

    bool Setup();
};

}
