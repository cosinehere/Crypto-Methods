#include "pch.h"

#include "RC6.h"

#include "CryptoTemplates.h"

NAMESPACE_BEGIN(CryptoMethods)

RC6::RC6() {
    p_method = enum_crypt_methods_rc6;
    p_blocksize = 16;

    p_haskey = false;
}

RC6::~RC6() {}

const size_t RC6::BlockSize() { return p_blocksize; }

bool RC6::SetKey(const uint8_t* key, const size_t keylen) {
    if (key == nullptr || keylen != c_rc6b) {
    return false;
    }

    memcpy(p_key, key, sizeof(uint8_t) * c_rc6b);

    bool bRet = Setup();
    if (bRet) {
    p_haskey = true;
    } else {
    p_haskey = false;
    }

    return bRet;
}

bool RC6::Encrypt(const uint8_t* plain, uint8_t* cipher) {
    if (!p_haskey) {
    return false;
    }

    rc6_word A = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(plain));
    rc6_word B = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&plain[4]));
    rc6_word C = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&plain[8]));
    rc6_word D = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&plain[12]));

    B += p_roundkey[0];
    D += p_roundkey[1];

    for (size_t i = 1; i <= c_rc6r; ++i) {
    rc6_word t = l_rot<rc6_word>((B * (2 * B + 1)), c_rc6lgw);
    rc6_word u = l_rot<rc6_word>((D * (2 * D + 1)), c_rc6lgw);
    A = l_rot<rc6_word>(A ^ t, u & 0x1f) + p_roundkey[2 * i];
    C = l_rot<rc6_word>(C ^ u, t & 0x1f) + p_roundkey[2 * i + 1];

    rc6_word tmp = A;
    A = B;
    B = C;
    C = D;
    D = tmp;
    }

    A += p_roundkey[2 * c_rc6r + 2];
    C += p_roundkey[2 * c_rc6r + 3];

    rc6_word* c0 = reinterpret_cast<rc6_word*>(cipher);
    rc6_word* c1 = reinterpret_cast<rc6_word*>(&cipher[4]);
    rc6_word* c2 = reinterpret_cast<rc6_word*>(&cipher[8]);
    rc6_word* c3 = reinterpret_cast<rc6_word*>(&cipher[12]);

    *c0 = A;
    *c1 = B;
    *c2 = C;
    *c3 = D;

    return true;
}

bool RC6::Decrypt(const uint8_t* cipher, uint8_t* plain) {
    if (!p_haskey) {
    return false;
    }

    rc6_word A = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(cipher));
    rc6_word B = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&cipher[4]));
    rc6_word C = *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&cipher[8]));
    rc6_word D =
    *reinterpret_cast<rc6_word*>(const_cast<uint8_t*>(&cipher[12]));

    A -= p_roundkey[2 * c_rc6r + 2];
    C -= p_roundkey[2 * c_rc6r + 3];

    for (size_t i = c_rc6r; i > 0; --i) {
    rc6_word tmp = D;
    D = C;
    C = B;
    B = A;
    A = tmp;

    rc6_word u = l_rot<rc6_word>((D * (2 * D + 1)), c_rc6lgw);
    rc6_word t = l_rot<rc6_word>((B * (2 * B + 1)), c_rc6lgw);
    C = r_rot<rc6_word>(C - p_roundkey[2 * i + 1], t & 0x1f) ^ u;
    A = r_rot<rc6_word>(A - p_roundkey[2 * i], u & 0x1f) ^ t;
    }

    B -= p_roundkey[0];
    D -= p_roundkey[1];

    rc6_word* c0 = reinterpret_cast<rc6_word*>(plain);
    rc6_word* c1 = reinterpret_cast<rc6_word*>(&plain[4]);
    rc6_word* c2 = reinterpret_cast<rc6_word*>(&plain[8]);
    rc6_word* c3 = reinterpret_cast<rc6_word*>(&plain[12]);

    *c0 = A;
    *c1 = B;
    *c2 = C;
    *c3 = D;

    return true;
}

bool RC6::Setup() {
    rc6_word L[c_rc6c] = {0};
    L[c_rc6c - 1] = 0;
    for (size_t i = c_rc6b - 1; i != -1; --i) {
    L[i / c_rc6u] = (L[i / c_rc6u] << 8) + p_key[i];
    }

    p_roundkey[0] = c_rc6Pw;
    for (size_t i = 1; i < c_rc6t; ++i) {
    p_roundkey[i] = p_roundkey[i - 1] + c_rc6Qw;
    }

    rc6_word A = 0, B = 0;
    for (size_t i = 0, j = 0, k = 0; k < 3 * c_rc6t;
     ++k, i = (i + 1) % c_rc6t, j = (j + 1) % c_rc6c) {
    A = p_roundkey[i] = l_rot<rc6_word>(p_roundkey[i] + A + B, 3);
    B = L[j] = l_rot<rc6_word>(L[j] + A + B, (A + B) & 0x1f);
    }

    return true;
}

NAMESPACE_END
