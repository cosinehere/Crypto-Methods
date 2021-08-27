#include "pch.h"
#include "SM4.h"

#include "CryptoTemplates.h"

namespace CryptoMethods {

constexpr size_t c_sm4blocksize = 16;

constexpr uint32_t FK[] = { 0xa3b1bac6ul, 0x56aa3350ul, 0x677d9197ul, 0xb27022dcul };

constexpr uint32_t CK[] = { 0x00070e15ul, 0x1c232a31ul, 0x383f464dul, 0x545b6269ul,
                            0x70777e85ul, 0x8c939aa1ul, 0xa8afb6bdul, 0xc4cbd2d9ul,
                            0xe0e7eef5ul, 0xfc030a11ul, 0x181f262dul, 0x343b4249ul,
                            0x50575e65ul, 0x6c737a81ul, 0x888f969dul, 0xa4abb2b9ul,
                            0xc0c7ced5ul, 0xdce3eaf1ul, 0xf8ff060dul, 0x141b2229ul,
                            0x30373e45ul, 0x4c535a61ul, 0x686f767dul, 0x848b9299ul,
                            0xa0a7aeb5ul, 0xbcc3cad1ul, 0xd8dfe6edul, 0xf4fb0209ul,
                            0x10171e25ul, 0x2c333a41ul, 0x484f565dul, 0x646b7279ul };

constexpr uint8_t SBox[] = { 0xd6u, 0x90u, 0xe9u, 0xfeu, 0xccu, 0xe1u, 0x3du, 0xb7u, 0x16u, 0xb6u, 0x14u, 0xc2u, 0x28u, 0xfbu, 0x2cu, 0x05u,
                            0x2bu, 0x67u, 0x9au, 0x76u, 0x2au, 0xbeu, 0x04u, 0xc3u, 0xaau, 0x44u, 0x13u, 0x26u, 0x49u, 0x86u, 0x06u, 0x99u,
                            0x9cu, 0x42u, 0x50u, 0xf4u, 0x91u, 0xefu, 0x98u, 0x7au, 0x33u, 0x54u, 0x0bu, 0x43u, 0xedu, 0xcfu, 0xacu, 0x62u,
                            0xe4u, 0xb3u, 0x1cu, 0xa9u, 0xc9u, 0x08u, 0xe8u, 0x95u, 0x80u, 0xdfu, 0x94u, 0xfau, 0x75u, 0x8fu, 0x3fu, 0xa6u,
                            0x47u, 0x07u, 0xa7u, 0xfcu, 0xf3u, 0x73u, 0x17u, 0xbau, 0x83u, 0x59u, 0x3cu, 0x19u, 0xe6u, 0x85u, 0x4fu, 0xa8u,
                            0x68u, 0x6bu, 0x81u, 0xb2u, 0x71u, 0x64u, 0xdau, 0x8bu, 0xf8u, 0xebu, 0x0fu, 0x4bu, 0x70u, 0x56u, 0x9du, 0x35u,
                            0x1eu, 0x24u, 0x0eu, 0x5eu, 0x63u, 0x58u, 0xd1u, 0xa2u, 0x25u, 0x22u, 0x7cu, 0x3bu, 0x01u, 0x21u, 0x78u, 0x87u,
                            0xd4u, 0x00u, 0x46u, 0x57u, 0x9fu, 0xd3u, 0x27u, 0x52u, 0x4cu, 0x36u, 0x02u, 0xe7u, 0xa0u, 0xc4u, 0xc8u, 0x9eu,
                            0xeau, 0xbfu, 0x8au, 0xd2u, 0x40u, 0xc7u, 0x38u, 0xb5u, 0xa3u, 0xf7u, 0xf2u, 0xceu, 0xf9u, 0x61u, 0x15u, 0xa1u,
                            0xe0u, 0xaeu, 0x5du, 0xa4u, 0x9bu, 0x34u, 0x1au, 0x55u, 0xadu, 0x93u, 0x32u, 0x30u, 0xf5u, 0x8cu, 0xb1u, 0xe3u,
                            0x1du, 0xf6u, 0xe2u, 0x2eu, 0x82u, 0x66u, 0xcau, 0x60u, 0xc0u, 0x29u, 0x23u, 0xabu, 0x0du, 0x53u, 0x4eu, 0x6fu,
                            0xd5u, 0xdbu, 0x37u, 0x45u, 0xdeu, 0xfdu, 0x8eu, 0x2fu, 0x03u, 0xffu, 0x6au, 0x72u, 0x6du, 0x6cu, 0x5bu, 0x51u,
                            0x8du, 0x1bu, 0xafu, 0x92u, 0xbbu, 0xddu, 0xbcu, 0x7fu, 0x11u, 0xd9u, 0x5cu, 0x41u, 0x1fu, 0x10u, 0x5au, 0xd8u,
                            0x0au, 0xc1u, 0x31u, 0x88u, 0xa5u, 0xcdu, 0x7bu, 0xbdu, 0x2du, 0x74u, 0xd0u, 0x12u, 0xb8u, 0xe5u, 0xb4u, 0xb0u,
                            0x89u, 0x69u, 0x97u, 0x4au, 0x0cu, 0x96u, 0x77u, 0x7eu, 0x65u, 0xb9u, 0xf1u, 0x09u, 0xc5u, 0x6eu, 0xc6u, 0x84u,
                            0x18u, 0xf0u, 0x7du, 0xecu, 0x3au, 0xdcu, 0x4du, 0x20u, 0x79u, 0xeeu, 0x5fu, 0x3eu, 0xd7u, 0xcbu, 0x39u, 0x48u };

inline uint32_t tao(uint32_t x) {
    return (SBox[(x >> 24) & 0xff] << 24) | (SBox[(x >> 16) & 0xff] << 16) | (SBox[(x >> 8) & 0xff] << 8) | SBox[x & 0xff];
}

inline uint32_t T(uint32_t x) {
    uint32_t B = tao(x);
    return B ^ l_rot<uint32_t>(B, 2) ^ l_rot<uint32_t>(B, 10) ^ l_rot<uint32_t>(B, 18) ^ l_rot<uint32_t>(B, 24);
}

inline uint32_t T1(uint32_t x) {
    uint32_t B = tao(x);
    return B ^ l_rot<uint32_t>(B, 13) ^ l_rot<uint32_t>(B, 23);
}

inline uint32_t F(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e) {
    return a ^ T(b ^ c ^ d ^ e);
}

inline void R(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    uint32_t temp = a;
    a = d;
    d = temp;
    temp = b;
    b = c;
    c = temp;
}

SM4::SM4() {
    p_method = enum_crypt_methods_aes;
    p_blocksize = c_sm4blocksize;

    p_haskey = false;
}

const size_t SM4::KeyLength(size_t *min, size_t *max) {
    if (min != nullptr) {
        *min = 16;
    }
    
    if (max != nullptr) {
        *max = 16;
    }

    return 16;
}

bool SM4::SetKey(const uint8_t *key, const size_t keylen) {
    if (key == nullptr || keylen != 16) {
        return false;
    }

    memcpy(p_key, key, sizeof(uint8_t) * keylen);

    bool bRet = KeyExpand();
    if (bRet) {
        p_haskey = true;
    }
    else {
        p_haskey = false;
    }

    return bRet;
}

bool SM4::Encrypt(const uint8_t *plain, uint8_t *cipher) {
    if (!p_haskey) {
        return false;
    }

    uint32_t X[36];
    for (int i = 0; i < 4; ++i) {
        X[i] = (plain[i * 4] << 24) | (plain[i * 4 + 1] << 16) | (plain[i * 4 + 2] << 8) | plain[i * 4 + 3];
    }

    for (int i = 0; i < 32; ++i) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], p_roundkey[i]);
    }

    R(X[32], X[33], X[34], X[35]);

    for (int i = 0; i < 16; ++i) {
        cipher[i] = X[32 + (i >> 2)] >> ((3 - (i % 4)) * 8) & 0xff;
    }

    return true;
}

bool SM4::Decrypt(const uint8_t *cipher, uint8_t *plain) {
    if (!p_haskey) {
        return false;
    }

    uint32_t X[36];
    for (int i = 0; i < 4; ++i) {
        X[i] = (cipher[i * 4] << 24) | (cipher[i * 4 + 1] << 16) | (cipher[i * 4 + 2] << 8) | cipher[i * 4 + 3];
    }

    for (int i = 0; i < 32; ++i) {
        X[i + 4] = F(X[i], X[i + 1], X[i + 2], X[i + 3], p_roundkey[31 - i]);
    }

    R(X[32], X[33], X[34], X[35]);

    for (int i = 0; i < 16; ++i) {
        plain[i] = X[32 + (i >> 2)] >> ((3 - (i % 4)) * 8) & 0xff;
    }

    return true;
}

bool SM4::KeyExpand() {
    uint32_t K[36];
    for (int i = 0; i < 4; ++i) {
        K[i] = ((p_key[i * 4] << 24) | (p_key[i * 4 + 1] << 16) | (p_key[i * 4 + 2] << 8) | (p_key[i * 4 + 3])) ^ FK[i];
    }
    for (int i = 0; i < 32; ++i) {
        p_roundkey[i] = K[i + 4] = K[i] ^ T1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    }
    return true;
}

}
