#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

class CFB : public CipherModeBase {
   public:
    CFB(CipherBase *base);
    virtual ~CFB();

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
    CFB(const CFB&) = delete;
    CFB(const CFB&&) = delete;
    CFB& operator=(const CFB&) = delete;
    CFB& operator=(const CFB&&) = delete;
#endif  // CXX11_NOT_SUPPORT

   private:
    enum_crypt_modes p_mode;

    CipherBase *p_cipher;
    size_t p_blocksize;

    uint8_t *p_iv;
    size_t p_ivlen;
    uint8_t *p_temp;
};

CFB::CFB(CipherBase *base) {
    p_mode = enum_crypt_mode_cfb;

    p_cipher = base;
    p_blocksize = p_cipher->BlockSize();

    p_iv = new uint8_t[p_blocksize];
    p_ivlen = p_blocksize;
    p_temp = new uint8_t[p_blocksize];
}

CFB::~CFB() {
    if (p_iv != nullptr) {
        delete[] p_iv;
    }

    if (p_temp != nullptr) {
        delete[] p_temp;
    }
}

bool CFB::SetKey(const uint8_t *key, const size_t keylen) {
    return p_cipher->SetKey(key, keylen);
}

bool CFB::SetIV(const uint8_t *iv, const size_t ivlen) {
    if (iv == nullptr || ivlen != p_ivlen) {
        return false;
    }

    memcpy(p_iv, iv, sizeof(uint8_t) * p_ivlen);

    return true;
}

bool CFB::Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
                  size_t& outlen) {
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (i + p_blocksize <= inlen) ? p_blocksize : (inlen - i);
        outlen += len;
        if (i == 0) {
            p_cipher->Encrypt(p_iv, p_temp);
        } else {
            p_cipher->Encrypt(&out[i - p_blocksize], p_temp);
        }

        for (size_t j = 0; j < len; ++j) {
            out[i + j] = p_temp[j] ^ in[i + j];
        }
    }

    return true;
}

bool CFB::Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
                  size_t& outlen) {
    outlen = 0;
    for (size_t i = 0; i < inlen; i += p_blocksize) {
        size_t len = (i + p_blocksize <= inlen) ? p_blocksize : (inlen - i);
        outlen += len;
        if (i == 0) {
            p_cipher->Encrypt(p_iv, p_temp);
        } else {
            p_cipher->Encrypt(&out[i - p_blocksize], p_temp);
        }

        for (size_t j = 0; j < len; ++j) {
            out[i + j] = p_temp[j] ^ in[i + j];
        }
    }

    return true;
}

bool CFB::GetTemp(uint8_t *temp, const uint32_t templen) {
    if (templen != p_blocksize) {
        return false;
    }

    memcpy(temp, p_temp, sizeof(uint8_t) * templen);

    return true;
}

NAMESPACE_END
