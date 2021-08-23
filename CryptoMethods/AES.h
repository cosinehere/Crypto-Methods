#pragma once
#include "CryptoMethodDefines.h"

namespace CryptoMethods {

class AES : public CipherBase {
public:
    AES();
    virtual ~AES() {};

    virtual const enum_crypt_methods CryptMethod() override { return p_method; }
    virtual const size_t BlockSize() override { return p_blocksize; }
    virtual const size_t KeyLength(size_t *min, size_t *max) override;
    virtual bool SetKey(const uint8_t *key, const size_t keylen) override;
    virtual bool Encrypt(const uint8_t *plain, uint8_t *cipher) override;
    virtual bool Decrypt(const uint8_t *cipher, uint8_t *plain) override;

private:
    enum_crypt_methods p_method;
    size_t p_blocksize;

    bool p_haskey;

    uint8_t p_key[32];
    size_t p_keylen;
    size_t p_rounds;

    uint8_t p_roundkey[240];
    size_t p_roundkeylen;

    bool KeyExpand();
};

}
