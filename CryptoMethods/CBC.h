#pragma once
#include "CryptoMethodDefines.h"
#include "Padding.h"

namespace CryptoMethods {

class CBC : public CipherModeBase {
public:
    CBC(CipherBase *base);
    virtual ~CBC();

    virtual const enum_crypt_modes CryptMode() override { return p_mode; }

    virtual bool SetKey(const uint8_t *key, const size_t keylen) override {
        return p_cipher->SetKey(key, keylen);
    }

    virtual bool SetIV(const uint8_t *iv, const size_t ivlen) override;

    virtual size_t GetKeyLength(size_t *min, size_t *max) override {
        return p_cipher->KeyLength(min, max);
    }

    virtual size_t GetBlockSize() override {
        return p_cipher->BlockSize();
    }

    virtual size_t GetVector(uint8_t *buffer, const uint32_t buflen) override;

    virtual bool Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) override;
    virtual bool Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) override;

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

    bool p_hasiv;
    uint8_t *p_iv;
};

CBC::CBC(CipherBase *base) {
    p_mode = enum_crypt_mode_cbc;

    p_cipher = base;
    p_blocksize = p_cipher->BlockSize();

    p_hasiv = false;
    p_iv = new uint8_t[p_blocksize];
}

CBC::~CBC() {
    if (p_iv != nullptr) {
        delete[] p_iv;
    }
}

bool CBC::SetIV(const uint8_t *iv, const size_t ivlen) {
    if (iv == nullptr || ivlen < p_blocksize) {
        return false;
    }

    memcpy(p_iv, iv, sizeof(uint8_t) * p_blocksize);
    p_hasiv = true;

    return true;
}

size_t CBC::GetVector(uint8_t *buffer, const uint32_t buflen) {
    if (buflen < p_blocksize) {
        return 0;
    }

    memcpy(buffer, p_iv, sizeof(uint8_t) * p_blocksize);

    return p_blocksize;
}

bool CBC::Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t &outlen) {
    if (in == nullptr || inlen == 0 || out == nullptr || !p_hasiv) {
        return false;
    }

    uint8_t *p_temp = new uint8_t[p_blocksize];
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        outlen += p_blocksize;
        for (size_t j = 0; j < p_blocksize; ++j) {
            p_temp[j] = p_iv[j] ^ in[i + j];
        }

        p_cipher->Encrypt(p_temp, &out[i]);

        memcpy(p_iv, &out[i], sizeof(uint8_t) * p_blocksize);
    }
    delete[] p_temp;

    return true;
}

bool CBC::Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t &outlen) {
    if (in == nullptr || inlen == 0 || out == nullptr || !p_hasiv) {
        return false;
    }

    uint8_t *p_temp = new uint8_t[p_blocksize];
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        outlen += p_blocksize;
        p_cipher->Decrypt(&in[i], p_temp);

        for (size_t j = 0; j < p_blocksize; ++j) {
            out[i + j] = p_temp[j] ^ p_iv[j];
        }

        memcpy(p_iv, &in[i], sizeof(uint8_t) * p_blocksize);
    }
    delete[] p_temp;

    return true;
}

}
