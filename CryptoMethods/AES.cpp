#include "pch.h"

#include "AES.h"

namespace CryptoMethods {

inline uint8_t gmult(uint8_t a, uint8_t b) {
    uint8_t p = 0, hbs = 0;
    for (size_t i = 0; i < 8; i++) {
        if (b & 1) p ^= a;

        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b;
        b >>= 1;
    }

    return (uint8_t)p;
}

inline void subbytes(uint8_t *state, const uint8_t *box) {
    for (size_t i = 0; i < 16; ++i) {
        state[i] = box[state[i]];
    }
}

inline void shiftrows(uint8_t *state) {
    uint8_t tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

inline void rshiftrows(uint8_t *state) {
    uint8_t tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = tmp;
}

inline void mixcolumns(uint8_t *state) {
    uint8_t tmp[4];
    for (size_t i = 0; i < 4; ++i) {
        tmp[0] = gmult(2, state[4 * i]) ^ gmult(3, state[4 * i + 1]) ^
            gmult(1, state[4 * i + 2]) ^ gmult(1, state[4 * i + 3]);
        tmp[1] = gmult(1, state[4 * i]) ^ gmult(2, state[4 * i + 1]) ^
            gmult(3, state[4 * i + 2]) ^ gmult(1, state[4 * i + 3]);
        tmp[2] = gmult(1, state[4 * i]) ^ gmult(1, state[4 * i + 1]) ^
            gmult(2, state[4 * i + 2]) ^ gmult(3, state[4 * i + 3]);
        tmp[3] = gmult(3, state[4 * i]) ^ gmult(1, state[4 * i + 1]) ^
            gmult(1, state[4 * i + 2]) ^ gmult(2, state[4 * i + 3]);
        state[4 * i] = tmp[0];
        state[4 * i + 1] = tmp[1];
        state[4 * i + 2] = tmp[2];
        state[4 * i + 3] = tmp[3];
    }
}

inline void rmixcolumns(uint8_t *state) {
    uint8_t tmp[4];
    for (size_t i = 0; i < 4; ++i) {
        tmp[0] = gmult(14, state[4 * i]) ^ gmult(11, state[4 * i + 1]) ^
            gmult(13, state[4 * i + 2]) ^ gmult(9, state[4 * i + 3]);
        tmp[1] = gmult(9, state[4 * i]) ^ gmult(14, state[4 * i + 1]) ^
            gmult(11, state[4 * i + 2]) ^ gmult(13, state[4 * i + 3]);
        tmp[2] = gmult(13, state[4 * i]) ^ gmult(9, state[4 * i + 1]) ^
            gmult(14, state[4 * i + 2]) ^ gmult(11, state[4 * i + 3]);
        tmp[3] = gmult(11, state[4 * i]) ^ gmult(13, state[4 * i + 1]) ^
            gmult(9, state[4 * i + 2]) ^ gmult(14, state[4 * i + 3]);
        state[4 * i] = tmp[0];
        state[4 * i + 1] = tmp[1];
        state[4 * i + 2] = tmp[2];
        state[4 * i + 3] = tmp[3];
    }
}

inline void addroundkey(uint8_t *state, const uint8_t *word) {
    for (size_t i = 0; i < 16; ++i) {
        state[i] ^= word[i];
    }
}

AES::AES() {
    p_method = enum_crypt_methods_aes;
    p_blocksize = 16;

    p_haskey = false;
}

AES::~AES() {}

const size_t AES::BlockSize() { return p_blocksize; }

const size_t AES::KeyLength(size_t *min, size_t *max) {
    if (min != nullptr) {
        *min = 16;
    }
    if (max != nullptr) {
        *max = 32;
    }

    return 16;
}

bool AES::SetKey(const uint8_t *key, const size_t keylen) {
    if (key == nullptr || (keylen != 16 && keylen != 24 && keylen != 32)) {
        return false;
    }

    p_keylen = keylen;
    memcpy(p_key, key, sizeof(uint8_t) * keylen);
    p_rounds = (p_keylen >> 2) + 6;

    bool bRet = KeyExpand();
    if (bRet) {
        p_haskey = true;
    }
    else {
        p_haskey = false;
    }

    return bRet;
}

bool AES::Encrypt(const uint8_t *plain, uint8_t *cipher) {
    if (!p_haskey) {
        return false;
    }

    memcpy(cipher, plain, sizeof(uint8_t) * 16);

    addroundkey(cipher, p_roundkey);

    for (size_t r = 1; r < p_rounds; ++r) {
        subbytes(cipher, SBox);
        shiftrows(cipher);
        mixcolumns(cipher);
        addroundkey(cipher, p_roundkey + (r << 4));
    }
    subbytes(cipher, SBox);
    shiftrows(cipher);
    addroundkey(cipher, p_roundkey + (p_rounds << 4));

    return true;
}

bool AES::Decrypt(const uint8_t *cipher, uint8_t *plain) {
    if (!p_haskey) {
        return false;
    }

    memcpy(plain, cipher, sizeof(uint8_t) * 16);

    addroundkey(plain, p_roundkey + (p_rounds << 4));

    for (size_t r = p_rounds - 1; r > 0; --r) {
        rshiftrows(plain);
        subbytes(plain, RSBox);
        addroundkey(plain, p_roundkey + (r << 4));
        rmixcolumns(plain);
    }
    rshiftrows(plain);
    subbytes(plain, RSBox);
    addroundkey(plain, p_roundkey);

    return true;
}

bool AES::KeyExpand() {
    p_roundkeylen = (p_rounds + 1) << 2;

    memcpy(p_roundkey, p_key, sizeof(uint8_t) * p_keylen);

    uint32_t mod = p_keylen >> 2;
    for (size_t i = mod; i < p_roundkeylen; ++i) {
        uint8_t temp[4] = {
            p_roundkey[(i - 1) << 2], p_roundkey[((i - 1) << 2) + 1],
            p_roundkey[((i - 1) << 2) + 2], p_roundkey[((i - 1) << 2) + 3] };
        if (!(i % mod)) {
            uint8_t tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tmp;

            temp[0] = SBox[temp[0]];
            temp[1] = SBox[temp[1]];
            temp[2] = SBox[temp[2]];
            temp[3] = SBox[temp[3]];

            temp[0] ^= Rcon[i / mod - 1][0];
            temp[1] ^= Rcon[i / mod - 1][1];
            temp[2] ^= Rcon[i / mod - 1][2];
            temp[3] ^= Rcon[i / mod - 1][3];
        }
        else if ((mod == 8) && ((i % mod) == 4)) {
            temp[0] = SBox[temp[0]];
            temp[1] = SBox[temp[1]];
            temp[2] = SBox[temp[2]];
            temp[3] = SBox[temp[3]];
        }

        p_roundkey[i << 2] = temp[0] ^ p_roundkey[(i - mod) << 2];
        p_roundkey[(i << 2) + 1] = temp[1] ^ p_roundkey[((i - mod) << 2) + 1];
        p_roundkey[(i << 2) + 2] = temp[2] ^ p_roundkey[((i - mod) << 2) + 2];
        p_roundkey[(i << 2) + 3] = temp[3] ^ p_roundkey[((i - mod) << 2) + 3];
    }

    return true;
}

}
