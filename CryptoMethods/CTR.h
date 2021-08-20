#pragma once
#include "CryptoMethodDefines.h"

namespace CryptoMethods {

class CTR : public CipherModeBase {
public:
    CTR(CipherBase *base);
    virtual ~CTR();

    virtual const enum_crypt_modes CryptMode() override { return p_mode; }

    virtual bool SetKey(const uint8_t *key, const size_t keylen) override;
    virtual bool SetIV(const uint8_t *iv, const size_t ivlen) override;

    virtual bool Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t& outlen) override;
    virtual bool Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t& outlen) override;

    virtual bool GetTemp(uint8_t *temp, const uint32_t templen) override;

    virtual size_t GetKeyLength(size_t *min, size_t *max) override {
        return p_cipher->KeyLength(min, max);
    }

    virtual size_t GetBlockSize() override {
        return p_cipher->BlockSize();
    }

#ifndef CXX11_NOT_SUPPORT
private:
    CTR(const CTR&) = delete;
    CTR(const CTR&&) = delete;
    CTR& operator=(const CTR&) = delete;
    CTR& operator=(const CTR&&) = delete;
#endif  // CXX11_NOT_SUPPORT

private:
    enum_crypt_modes p_mode;

    CipherBase *p_cipher;
    size_t p_blocksize;

    uint8_t *p_iv;
    size_t p_ivlen;
    uint8_t *p_temp;
};

CTR::CTR(CipherBase *base) {
    p_mode = enum_crypt_mode_ctr;

    p_cipher = base;
    p_blocksize = p_cipher->BlockSize();

    p_iv = new uint8_t[p_blocksize];
    p_ivlen = p_blocksize;
    p_temp = new uint8_t[p_blocksize];
}

CTR::~CTR() {
    if (p_iv != nullptr) {
        delete[] p_iv;
    }

    if (p_temp != nullptr) {
        delete[] p_temp;
    }
}

bool CTR::SetKey(const uint8_t *key, const size_t keylen) {
    return p_cipher->SetKey(key, keylen);
}

bool CTR::SetIV(const uint8_t *iv, const size_t ivlen) {
    if (iv == nullptr || ivlen != p_ivlen) {
        return false;
    }

    memcpy(p_iv, iv, sizeof(uint8_t) * p_ivlen);

    return true;
}

bool CTR::Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t& outlen) {
    uint8_t *counter = new uint8_t[p_blocksize];
    memcpy(counter, p_iv, sizeof(uint8_t) * p_blocksize);
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (inlen - i > p_blocksize) ? p_blocksize : (inlen - i);
        outlen += len;
        p_cipher->Encrypt(counter, p_temp);

        for (size_t j = 0; j < len; ++j) {
            out[i + j] = p_temp[j] ^ in[i + j];
        }

        uint32_t cnt = (uint32_t)counter[p_blocksize - 1] |
            ((uint32_t)counter[p_blocksize - 2] << 8) |
            ((uint32_t)counter[p_blocksize - 3] << 16) |
            ((uint32_t)counter[p_blocksize - 4] << 24);
        cnt++;
        counter[p_blocksize - 1] = cnt & 0xff;
        counter[p_blocksize - 2] = (cnt >> 8) & 0xff;
        counter[p_blocksize - 3] = (cnt >> 16) & 0xff;
        counter[p_blocksize - 4] = (cnt >> 24) & 0xff;
    }
    delete[] counter;

    return true;
}

bool CTR::Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t& outlen) {
    uint8_t *counter = new uint8_t[p_blocksize];
    memcpy(counter, p_iv, sizeof(uint8_t) * p_blocksize);
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (inlen - i > p_blocksize) ? p_blocksize : (inlen - i);
        outlen += len;
        p_cipher->Encrypt(counter, p_temp);

        for (size_t j = 0; j < len; ++j) {
            out[i + j] = p_temp[j] ^ in[i + j];
        }

        uint32_t cnt = (uint32_t)counter[p_blocksize - 1] |
            ((uint32_t)counter[p_blocksize - 2] << 8) |
            ((uint32_t)counter[p_blocksize - 3] << 16) |
            ((uint32_t)counter[p_blocksize - 4] << 24);
        cnt++;
        counter[p_blocksize - 1] = cnt & 0xff;
        counter[p_blocksize - 2] = (cnt >> 8) & 0xff;
        counter[p_blocksize - 3] = (cnt >> 16) & 0xff;
        counter[p_blocksize - 4] = (cnt >> 24) & 0xff;
    }
    delete[] counter;

    return true;
}

bool CTR::GetTemp(uint8_t *temp, const uint32_t templen) {
    if (templen != p_blocksize) {
        return false;
    }

    memcpy(temp, p_temp, sizeof(uint8_t) * templen);

    return true;
}

}
