#pragma once
#include "CryptoMethodDefines.h"
#include "Padding.h"

namespace CryptoMethods {

class CBC : public CipherModeBase {
public:
    CBC(CipherBase *base);
    virtual ~CBC();

    virtual const enum_crypt_modes CryptMode() override { return p_mode; }

    virtual bool SetKey(const uint8_t *key, const size_t keylen) override;
    virtual bool SetIV(const uint8_t *iv, const size_t ivlen) override;

    virtual bool Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) override;
    virtual bool Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) override;

    virtual bool GetTemp(uint8_t *temp, const uint32_t templen) override;

    virtual size_t GetKeyLength(size_t *min, size_t *max) override {
        return p_cipher->KeyLength(min, max);
    }

    virtual size_t GetBlockSize() override {
        return p_cipher->BlockSize();
    }

#ifndef CXX11_NOT_SUPPORT
private:
    CBC(const CBC&) = delete;
    CBC(const CBC&&) = delete;
    CBC& operator=(const CBC&) = delete;
    CBC& operator=(const CBC&&) = delete;
#endif  // CXX11_NOT_SUPPORT

private:
    enum_crypt_modes p_mode;

    CipherBase *p_cipher;
    size_t p_blocksize;

    uint8_t *p_iv;
    size_t p_ivlen;
    uint8_t *p_temp;
};

CBC::CBC(CipherBase *base) {
    p_mode = enum_crypt_mode_cbc;

    p_cipher = base;
    p_blocksize = p_cipher->BlockSize();

    p_iv = new uint8_t[p_blocksize];
    p_ivlen = p_blocksize;
    p_temp = new uint8_t[p_blocksize];
}

CBC::~CBC() {
    if (p_iv != nullptr) {
        delete[] p_iv;
    }

    if (p_temp != nullptr) {
        delete[] p_temp;
    }
}

bool CBC::SetKey(const uint8_t *key, const size_t keylen) {
    return p_cipher->SetKey(key, keylen);
}

bool CBC::SetIV(const uint8_t *iv, const size_t ivlen) {
    if (iv == nullptr || ivlen != p_ivlen) {
        return false;
    }

    memcpy(p_iv, iv, sizeof(uint8_t) * p_ivlen);

    return true;
}

bool CBC::Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t& outlen) {
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        outlen += p_blocksize;
        if (i == 0) {
            for (size_t j = 0; j < p_blocksize; ++j) {
                p_temp[j] = in[j] ^ p_iv[j];
            }
        }
        else {
            for (size_t j = 0; j < p_blocksize; ++j) {
                p_temp[j] = out[i - p_blocksize + j] ^ in[i + j];
            }
        }

        p_cipher->Encrypt(p_temp, &out[i]);
    }

    return true;
}

bool CBC::Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t& outlen) {
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        outlen += p_blocksize;
        p_cipher->Decrypt(&in[i], p_temp);
        if (i == 0) {
            for (size_t j = 0; j < p_blocksize; ++j) {
                out[j] = p_temp[j] ^ p_iv[j];
            }
        }
        else {
            for (size_t j = 0; j < p_blocksize; ++j) {
                out[i + j] = p_temp[j] ^ in[i - p_blocksize + j];
            }
        }
    }

    return true;
}

bool CBC::GetTemp(uint8_t *temp, const uint32_t templen) {
    if (templen != p_blocksize) {
        return false;
    }

    memcpy(temp, p_temp, sizeof(uint8_t) * templen);

    return true;
}

}
