#include "pch.h"

#include "CryptoMethodDefines.h"

#include "AES.h"
#include "Blowfish.h"
#include "CBC.h"
#include "CFB.h"
#include "CTR.h"
#include "Camellia.h"
#include "DES.h"
#include "RC5.h"
#include "RC6.h"
#include "TripDES.h"
#include "Twofish.h"

namespace CryptoMethods {

void GenerateIV(uint8_t *iv, size_t ivlen) {
#if defined(_MSC_VER)
    HCRYPTPROV crypt;
    CryptAcquireContext(&crypt, nullptr, nullptr, PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT);
    CryptGenRandom(crypt, ivlen, iv);
    CryptReleaseContext(crypt, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, iv, sizeof(uint8_t) * ivlen);
    close(fd);
#endif
}

void MixBytes(uint8_t *key, uint8_t *iv, uint8_t *cipher, size_t cipherlen,
              uint8_t *mix) {
    GenerateIV(mix, 8);
    for (size_t i = 0; i < 4; ++i) {
        uint32_t pos =
            *reinterpret_cast<uint32_t *>(&mix[i]) % (4 + cipherlen / 8);
        uint64_t *cur = nullptr;
        uint64_t *post = nullptr;
        if (i < 2) {
            cur = reinterpret_cast<uint64_t *>(&key[i * 8]);
        } else {
            cur = reinterpret_cast<uint64_t *>(&iv[(i - 2) * 8]);
        }

        if (pos < 2) {
            post = reinterpret_cast<uint64_t *>(&key[pos * 8]);
        } else if (pos < 4) {
            post = reinterpret_cast<uint64_t *>(&iv[(pos - 2) * 8]);
        } else {
            post = reinterpret_cast<uint64_t *>(&cipher[(pos - 4) * 8]);
        }

        uint64_t tmp = *cur;
        *cur = *post;
        *post = tmp;
    }
}

void ScatterBytes(uint8_t *key, uint8_t *iv, uint8_t *cipher, size_t cipherlen,
                  uint8_t *mix) {
    for (int i = 3; i >= 0; --i) {
        uint32_t pos =
            *reinterpret_cast<uint32_t *>(&mix[i]) % (4 + cipherlen / 8);
        uint64_t *cur = nullptr;
        uint64_t *post = nullptr;
        if (i < 2) {
            cur = reinterpret_cast<uint64_t *>(&key[i * 8]);
        } else {
            cur = reinterpret_cast<uint64_t *>(&iv[(i - 2) * 8]);
        }

        if (pos < 2) {
            post = reinterpret_cast<uint64_t *>(&key[pos * 8]);
        } else if (pos < 4) {
            post = reinterpret_cast<uint64_t *>(&iv[(pos - 2) * 8]);
        } else {
            post = reinterpret_cast<uint64_t *>(&cipher[(pos - 4) * 8]);
        }

        uint64_t tmp = *cur;
        *cur = *post;
        *post = tmp;
    }
}

void CreateCipherBase(enum_crypt_methods method, CipherBase *&base) {
    switch (method) {
    case CryptoMethods::enum_crypt_methods_des:
        base = new DES();
        break;
    case CryptoMethods::enum_crypt_methods_tripdes:
        base = new TripDES();
        break;
    case CryptoMethods::enum_crypt_methods_aes:
        base = new AES();
        break;
    case CryptoMethods::enum_crypt_methods_rc5:
        base = new RC5();
        break;
    case CryptoMethods::enum_crypt_methods_rc6:
        base = new RC6();
        break;
    case CryptoMethods::enum_crypt_methods_camellia:
        base = new Camellia();
        break;
    case CryptoMethods::enum_crypt_methods_blowfish:
        base = new Blowfish();
        break;
    case CryptoMethods::enum_crypt_methods_twofish:
        base = new Twofish();
        break;
    default:
        break;
    }
}

void ReleaseCipherBase(CipherBase *&base) {
    switch (base->CryptMethod()) {
    case CryptoMethods::enum_crypt_methods_des:
        delete static_cast<DES *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_tripdes:
        delete static_cast<TripDES *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_aes:
        delete static_cast<AES *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_rc5:
        delete static_cast<RC5 *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_rc6:
        delete static_cast<RC6 *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_camellia:
        delete static_cast<Camellia *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_blowfish:
        delete static_cast<Blowfish *>(base);
        break;
    case CryptoMethods::enum_crypt_methods_twofish:
        delete static_cast<Twofish *>(base);
        break;
    default:
        break;
    }
}

void CreateCipherMode(enum_crypt_modes mode, CipherBase *cipher,
                      CipherModeBase *&base) {
    switch (mode) {
    case CryptoMethods::enum_crypt_mode_cbc:
        base = new CBC(cipher);
        break;
    case CryptoMethods::enum_crypt_mode_cfb:
        base = new CFB(cipher);
        break;
    case CryptoMethods::enum_crypt_mode_ctr:
        base = new CTR(cipher);
        break;
    default:
        break;
    }
}

void ReleaseCipherMode(CipherModeBase *&base) {
    switch (base->CryptMode()) {
    case CryptoMethods::enum_crypt_mode_cbc:
        delete static_cast<CBC *>(base);
        break;
    case CryptoMethods::enum_crypt_mode_cfb:
        delete static_cast<CFB *>(base);
        break;
    case CryptoMethods::enum_crypt_mode_ctr:
        delete static_cast<CTR *>(base);
        break;
    default:
        break;
    }
}

} // namespace CryptoMethods

