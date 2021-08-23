#pragma once
#include "CryptoMethodDefines.h"

namespace CryptoMethods {

class CTR : public CipherModeBase {
public:
    CTR(CipherBase *base);
    virtual ~CTR();

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
    CTR(const CTR&) = delete;
    CTR(const CTR&&) = delete;
    CTR& operator=(const CTR&) = delete;
    CTR& operator=(const CTR&&) = delete;
#endif  // CXX11_NOT_SUPPORT

private:
    enum_crypt_modes p_mode;

    CipherBase *p_cipher;
    size_t p_blocksize;

    bool p_hasiv;
    uint8_t *p_iv;
};

CTR::CTR(CipherBase *base) {
    p_mode = enum_crypt_mode_ctr;

    p_cipher = base;
    p_blocksize = p_cipher->BlockSize();

    p_hasiv = false;
    p_iv = new uint8_t[p_blocksize];
}

CTR::~CTR() {
    if (p_iv != nullptr) {
        delete[] p_iv;
    }
}

bool CTR::SetIV(const uint8_t *iv, const size_t ivlen) {
    if (iv == nullptr || ivlen < p_blocksize) {
        return false;
    }

    memcpy(p_iv, iv, sizeof(uint8_t) * p_blocksize);
    p_hasiv = true;

    return true;
}

size_t CTR::GetVector(uint8_t *buffer, const uint32_t buflen) {
    if (buflen < p_blocksize) {
        return 0;
    }

    memcpy(buffer, p_iv, sizeof(uint8_t) * p_blocksize);

    return p_blocksize;
}

bool CTR::Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t &outlen) {
    if (in == nullptr || inlen == 0 || out == nullptr || !p_hasiv) {
        return false;
    }

    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (inlen - i > p_blocksize) ? p_blocksize : (inlen - i);
        outlen += len;
        p_cipher->Encrypt(p_iv, &out[i]);

        for (size_t j = 0; j < len; ++j) {
            out[i + j] ^= in[i + j];
        }

        for (size_t j = p_blocksize; j > 0; --j) {
            p_iv[j - 1]++;
            if (p_iv[j - 1]) {
                break;
            }
        }
    }

    return true;
}

bool CTR::Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
    size_t& outlen) {
    if (in == nullptr || inlen == 0 || out == nullptr || !p_hasiv) {
        return false;
    }

    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (inlen - i > p_blocksize) ? p_blocksize : (inlen - i);
        outlen += len;
        p_cipher->Encrypt(p_iv, &out[i]);

        for (size_t j = 0; j < len; ++j) {
            out[i + j] ^= in[i + j];
        }

        for (size_t j = p_blocksize; j > 0; --j) {
            p_iv[j - 1]++;
            if (p_iv[j - 1]) {
                break;
            }
        }
    }

    return true;
}

}
