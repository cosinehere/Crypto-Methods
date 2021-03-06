#pragma once

#if defined(_MSC_VER)
#ifdef _CRYPTOMETHODSLIB_EXPORT_
#define CRYPTOEXT
#elif defined(_CRYPTOMETHODSDLL_EXPORT_)
#define CRYPTOEXT __declspec(dllexport)
#else
#define CRYPTOEXT __declspec(dllimport)
#endif

#define NOVTABLE __declspec(novtable)

#else
#ifdef _CRYPTOMETHODSDLL_EXPORT_
#define CRYPTOEXT __attribute__((visibility("default")))
#else
#define CRYPTOEXT
#endif

#define NOVTABLE
#endif

namespace CryptoMethods {

CRYPTOEXT void GenerateIV(uint8_t *iv, size_t ivlen);

CRYPTOEXT void MixBytes(uint8_t *key, uint8_t *iv, uint8_t *cipher,
    size_t cipherlen, uint8_t *mix);
CRYPTOEXT void ScatterBytes(uint8_t *key, uint8_t *iv, uint8_t *cipher,
    size_t cipherlen, uint8_t *mix);

enum enum_crypt_methods {
    enum_crypt_methods_des = 0,
    enum_crypt_methods_tripdes,
    enum_crypt_methods_aes,
    enum_crypt_methods_rc5,
    enum_crypt_methods_rc6,
    enum_crypt_methods_camellia,
    enum_crypt_methods_blowfish,
    enum_crypt_methods_twofish,
    enum_crypt_methods_sm4,

    enum_crypt_methods_end,
    enum_crypt_methods_num = enum_crypt_methods_end - enum_crypt_methods_des
};

enum enum_crypt_modes {
    enum_crypt_mode_cbc = 0,
    enum_crypt_mode_cfb,
    enum_crypt_mode_ctr,

    enum_crypt_mode_end,
    enum_crypt_mode_num = enum_crypt_mode_end - enum_crypt_mode_cbc,
};

class NOVTABLE CipherBase {
public:
    virtual const enum_crypt_methods CryptMethod() = 0;
    virtual const size_t BlockSize() = 0;
    virtual const size_t KeyLength(size_t *min, size_t *max) = 0;

    virtual bool SetKey(const uint8_t *key, const size_t keylen) = 0;
    virtual bool Encrypt(const uint8_t *plain, uint8_t *cipher) = 0;
    virtual bool Decrypt(const uint8_t *cipher, uint8_t *plain) = 0;

    virtual ~CipherBase() {}
};

class NOVTABLE CipherModeBase {
public:
    virtual ~CipherModeBase() {}

    virtual const enum_crypt_modes CryptMode() = 0;

    virtual bool SetKey(const uint8_t *key, const size_t keylen) = 0;
    virtual bool SetIV(const uint8_t *iv, const size_t ivlen) = 0;

    virtual size_t GetKeyLength(size_t *min, size_t *max) = 0;
    virtual size_t GetBlockSize() = 0;
    virtual size_t GetVector(uint8_t *buffer, const uint32_t buflen) = 0;

    virtual bool Encrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) = 0;
    virtual bool Decrypt(const uint8_t *in, const size_t inlen, uint8_t *out,
        size_t &outlen) = 0;
};

CRYPTOEXT void CreateCipherBase(enum_crypt_methods method, CipherBase*& base);
CRYPTOEXT void ReleaseCipherBase(CipherBase*& base);

CRYPTOEXT void CreateCipherMode(enum_crypt_modes mode, CipherBase *cipher,
    CipherModeBase*& base);
CRYPTOEXT void ReleaseCipherMode(CipherModeBase*& base);

}
