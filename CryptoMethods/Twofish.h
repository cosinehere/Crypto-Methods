#pragma once
#include "CryptoMethodDefines.h"

namespace CryptoMethods {

constexpr size_t c_twofishblocksize = 16;

constexpr uint8_t c_Qtab[2][256] = {
    {
        0xa9u, 0x67u, 0xb3u, 0xe8u, 0x04u, 0xfdu, 0xa3u, 0x76u, 0x9au, 0x92u, 0x80u, 0x78u,
        0xe4u, 0xddu, 0xd1u, 0x38u, 0x0du, 0xc6u, 0x35u, 0x98u, 0x18u, 0xf7u, 0xecu, 0x6cu,
        0x43u, 0x75u, 0x37u, 0x26u, 0xfau, 0x13u, 0x94u, 0x48u, 0xf2u, 0xd0u, 0x8bu, 0x30u,
        0x84u, 0x54u, 0xdfu, 0x23u, 0x19u, 0x5bu, 0x3du, 0x59u, 0xf3u, 0xaeu, 0xa2u, 0x82u,
        0x63u, 0x01u, 0x83u, 0x2eu, 0xd9u, 0x51u, 0x9bu, 0x7cu, 0xa6u, 0xebu, 0xa5u, 0xbeu,
        0x16u, 0x0cu, 0xe3u, 0x61u, 0xc0u, 0x8cu, 0x3au, 0xf5u, 0x73u, 0x2cu, 0x25u, 0x0bu,
        0xbbu, 0x4eu, 0x89u, 0x6bu, 0x53u, 0x6au, 0xb4u, 0xf1u, 0xe1u, 0xe6u, 0xbdu, 0x45u,
        0xe2u, 0xf4u, 0xb6u, 0x66u, 0xccu, 0x95u, 0x03u, 0x56u, 0xd4u, 0x1cu, 0x1eu, 0xd7u,
        0xfbu, 0xc3u, 0x8eu, 0xb5u, 0xe9u, 0xcfu, 0xbfu, 0xbau, 0xeau, 0x77u, 0x39u, 0xafu,
        0x33u, 0xc9u, 0x62u, 0x71u, 0x81u, 0x79u, 0x09u, 0xadu, 0x24u, 0xcdu, 0xf9u, 0xd8u,
        0xe5u, 0xc5u, 0xb9u, 0x4du, 0x44u, 0x08u, 0x86u, 0xe7u, 0xa1u, 0x1du, 0xaau, 0xedu,
        0x06u, 0x70u, 0xb2u, 0xd2u, 0x41u, 0x7bu, 0xa0u, 0x11u, 0x31u, 0xc2u, 0x27u, 0x90u,
        0x20u, 0xf6u, 0x60u, 0xffu, 0x96u, 0x5cu, 0xb1u, 0xabu, 0x9eu, 0x9cu, 0x52u, 0x1bu,
        0x5fu, 0x93u, 0x0au, 0xefu, 0x91u, 0x85u, 0x49u, 0xeeu, 0x2du, 0x4fu, 0x8fu, 0x3bu,
        0x47u, 0x87u, 0x6du, 0x46u, 0xd6u, 0x3eu, 0x69u, 0x64u, 0x2au, 0xceu, 0xcbu, 0x2fu,
        0xfcu, 0x97u, 0x05u, 0x7au, 0xacu, 0x7fu, 0xd5u, 0x1au, 0x4bu, 0x0eu, 0xa7u, 0x5au,
        0x28u, 0x14u, 0x3fu, 0x29u, 0x88u, 0x3cu, 0x4cu, 0x02u, 0xb8u, 0xdau, 0xb0u, 0x17u,
        0x55u, 0x1fu, 0x8au, 0x7du, 0x57u, 0xc7u, 0x8du, 0x74u, 0xb7u, 0xc4u, 0x9fu, 0x72u,
        0x7eu, 0x15u, 0x22u, 0x12u, 0x58u, 0x07u, 0x99u, 0x34u, 0x6eu, 0x50u, 0xdeu, 0x68u,
        0x65u, 0xbcu, 0xdbu, 0xf8u, 0xc8u, 0xa8u, 0x2bu, 0x40u, 0xdcu, 0xfeu, 0x32u, 0xa4u,
        0xcau, 0x10u, 0x21u, 0xf0u, 0xd3u, 0x5du, 0x0fu, 0x00u, 0x6fu, 0x9du, 0x36u, 0x42u,
        0x4au, 0x5eu, 0xc1u, 0xe0u,
    },
    {
        0x75u, 0xf3u, 0xc6u, 0xf4u, 0xdbu, 0x7bu, 0xfbu, 0xc8u, 0x4au, 0xd3u, 0xe6u, 0x6bu,
        0x45u, 0x7du, 0xe8u, 0x4bu, 0xd6u, 0x32u, 0xd8u, 0xfdu, 0x37u, 0x71u, 0xf1u, 0xe1u,
        0x30u, 0x0fu, 0xf8u, 0x1bu, 0x87u, 0xfau, 0x06u, 0x3fu, 0x5eu, 0xbau, 0xaeu, 0x5bu,
        0x8au, 0x00u, 0xbcu, 0x9du, 0x6du, 0xc1u, 0xb1u, 0x0eu, 0x80u, 0x5du, 0xd2u, 0xd5u,
        0xa0u, 0x84u, 0x07u, 0x14u, 0xb5u, 0x90u, 0x2cu, 0xa3u, 0xb2u, 0x73u, 0x4cu, 0x54u,
        0x92u, 0x74u, 0x36u, 0x51u, 0x38u, 0xb0u, 0xbdu, 0x5au, 0xfcu, 0x60u, 0x62u, 0x96u,
        0x6cu, 0x42u, 0xf7u, 0x10u, 0x7cu, 0x28u, 0x27u, 0x8cu, 0x13u, 0x95u, 0x9cu, 0xc7u,
        0x24u, 0x46u, 0x3bu, 0x70u, 0xcau, 0xe3u, 0x85u, 0xcbu, 0x11u, 0xd0u, 0x93u, 0xb8u,
        0xa6u, 0x83u, 0x20u, 0xffu, 0x9fu, 0x77u, 0xc3u, 0xccu, 0x03u, 0x6fu, 0x08u, 0xbfu,
        0x40u, 0xe7u, 0x2bu, 0xe2u, 0x79u, 0x0cu, 0xaau, 0x82u, 0x41u, 0x3au, 0xeau, 0xb9u,
        0xe4u, 0x9au, 0xa4u, 0x97u, 0x7eu, 0xdau, 0x7au, 0x17u, 0x66u, 0x94u, 0xa1u, 0x1du,
        0x3du, 0xf0u, 0xdeu, 0xb3u, 0x0bu, 0x72u, 0xa7u, 0x1cu, 0xefu, 0xd1u, 0x53u, 0x3eu,
        0x8fu, 0x33u, 0x26u, 0x5fu, 0xecu, 0x76u, 0x2au, 0x49u, 0x81u, 0x88u, 0xeeu, 0x21u,
        0xc4u, 0x1au, 0xebu, 0xd9u, 0xc5u, 0x39u, 0x99u, 0xcdu, 0xadu, 0x31u, 0x8bu, 0x01u,
        0x18u, 0x23u, 0xddu, 0x1fu, 0x4eu, 0x2du, 0xf9u, 0x48u, 0x4fu, 0xf2u, 0x65u, 0x8eu,
        0x78u, 0x5cu, 0x58u, 0x19u, 0x8du, 0xe5u, 0x98u, 0x57u, 0x67u, 0x7fu, 0x05u, 0x64u,
        0xafu, 0x63u, 0xb6u, 0xfeu, 0xf5u, 0xb7u, 0x3cu, 0xa5u, 0xceu, 0xe9u, 0x68u, 0x44u,
        0xe0u, 0x4du, 0x43u, 0x69u, 0x29u, 0x2eu, 0xacu, 0x15u, 0x59u, 0xa8u, 0x0au, 0x9eu,
        0x6eu, 0x47u, 0xdfu, 0x34u, 0x35u, 0x6au, 0xcfu, 0xdcu, 0x22u, 0xc9u, 0xc0u, 0x9bu,
        0x89u, 0xd4u, 0xedu, 0xabu, 0x12u, 0xa2u, 0x0du, 0x52u, 0xbbu, 0x02u, 0x2fu, 0xa9u,
        0xd7u, 0x61u, 0x1eu, 0xb4u, 0x50u, 0x04u, 0xf6u, 0xc2u, 0x16u, 0x25u, 0x86u, 0x56u,
        0x55u, 0x09u, 0xbeu, 0x91u,
    } };

/* 2. Standard interface for AES cryptographic routines             */

/* These are all based on 32 bit unsigned values and will therefore */

/* require endian conversions for big-endian architectures          */

/* 3. Basic macros for speeding up generic operations               */

/* Circular rotate of 32 bit values                                 */
#define rotr(x, n) r_rot<uint32_t>(x, n)
#define rotl(x, n) l_rot<uint32_t>(x, n)

// #ifdef _MSC_VER
// #  include <stdlib.h>
// #  pragma intrinsic(_lrotr,_lrotl)
// #  define rotr(x,n) _lrotr(x,n)
// #  define rotl(x,n) _lrotl(x,n)
// #else
// #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
// #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
// #endif

/* Invert byte order in a 32 bit variable                           */
#define bswap(x) (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)

/* Extract byte from a 32 bit quantity (little endian notation)     */
inline uint8_t byte(uint32_t x, uint32_t n) { return x >> (n << 3); }

/* For inverting byte order in input/output 32 bit words if needed  */
#ifdef BLOCK_SWAP
#define BYTE_SWAP
#define WORD_SWAP
#endif

#ifdef BYTE_SWAP
#define io_swap(x) bswap(x)
#else
#define io_swap(x) (x)
#endif

/* For inverting the byte order of input/output blocks if needed    */
#ifdef WORD_SWAP

#define get_block(x)                          \
    ((uint32_t*)(x))[0] = io_swap(in_blk[3]); \
    ((uint32_t*)(x))[1] = io_swap(in_blk[2]); \
    ((uint32_t*)(x))[2] = io_swap(in_blk[1]); \
    ((uint32_t*)(x))[3] = io_swap(in_blk[0])

#define put_block(x)                           \
    out_blk[3] = io_swap(((uint32_t*)(x))[0]); \
    out_blk[2] = io_swap(((uint32_t*)(x))[1]); \
    out_blk[1] = io_swap(((uint32_t*)(x))[2]); \
    out_blk[0] = io_swap(((uint32_t*)(x))[3])

#define get_key(x, len)                                               \
    ((uint32_t*)(x))[4] = ((uint32_t*)(x))[5] = ((uint32_t*)(x))[6] = \
        ((uint32_t*)(x))[7] = 0;                                      \
    switch ((((len) + 63) / 64)) {                                    \
        case 2:                                                       \
            ((uint32_t*)(x))[0] = io_swap(in_key[3]);                 \
            ((uint32_t*)(x))[1] = io_swap(in_key[2]);                 \
            ((uint32_t*)(x))[2] = io_swap(in_key[1]);                 \
            ((uint32_t*)(x))[3] = io_swap(in_key[0]);                 \
            break;                                                    \
        case 3:                                                       \
            ((uint32_t*)(x))[0] = io_swap(in_key[5]);                 \
            ((uint32_t*)(x))[1] = io_swap(in_key[4]);                 \
            ((uint32_t*)(x))[2] = io_swap(in_key[3]);                 \
            ((uint32_t*)(x))[3] = io_swap(in_key[2]);                 \
            ((uint32_t*)(x))[4] = io_swap(in_key[1]);                 \
            ((uint32_t*)(x))[5] = io_swap(in_key[0]);                 \
            break;                                                    \
        case 4:                                                       \
            ((uint32_t*)(x))[0] = io_swap(in_key[7]);                 \
            ((uint32_t*)(x))[1] = io_swap(in_key[6]);                 \
            ((uint32_t*)(x))[2] = io_swap(in_key[5]);                 \
            ((uint32_t*)(x))[3] = io_swap(in_key[4]);                 \
            ((uint32_t*)(x))[4] = io_swap(in_key[3]);                 \
            ((uint32_t*)(x))[5] = io_swap(in_key[2]);                 \
            ((uint32_t*)(x))[6] = io_swap(in_key[1]);                 \
            ((uint32_t*)(x))[7] = io_swap(in_key[0]);                 \
    }

#else

#define get_block(x)                          \
    ((uint32_t*)(x))[0] = io_swap(in_blk[0]); \
    ((uint32_t*)(x))[1] = io_swap(in_blk[1]); \
    ((uint32_t*)(x))[2] = io_swap(in_blk[2]); \
    ((uint32_t*)(x))[3] = io_swap(in_blk[3])

#define put_block(x)                           \
    out_blk[0] = io_swap(((uint32_t*)(x))[0]); \
    out_blk[1] = io_swap(((uint32_t*)(x))[1]); \
    out_blk[2] = io_swap(((uint32_t*)(x))[2]); \
    out_blk[3] = io_swap(((uint32_t*)(x))[3])

#define get_key(x, len)                                               \
    ((uint32_t*)(x))[4] = ((uint32_t*)(x))[5] = ((uint32_t*)(x))[6] = \
        ((uint32_t*)(x))[7] = 0;                                      \
    switch ((((len) + 63) / 64)) {                                    \
        case 4:                                                       \
            ((uint32_t*)(x))[6] = io_swap(in_key[6]);                 \
            ((uint32_t*)(x))[7] = io_swap(in_key[7]);                 \
        case 3:                                                       \
            ((uint32_t*)(x))[4] = io_swap(in_key[4]);                 \
            ((uint32_t*)(x))[5] = io_swap(in_key[5]);                 \
        case 2:                                                       \
            ((uint32_t*)(x))[0] = io_swap(in_key[0]);                 \
            ((uint32_t*)(x))[1] = io_swap(in_key[1]);                 \
            ((uint32_t*)(x))[2] = io_swap(in_key[2]);                 \
            ((uint32_t*)(x))[3] = io_swap(in_key[3]);                 \
    }

#endif

class Twofish : public CipherBase {
public:
    Twofish();
    virtual ~Twofish();

    virtual const enum_crypt_methods CryptMethod() override { return p_method; }
    virtual const size_t BlockSize() override;
    virtual const size_t KeyLength(size_t *min, size_t *max) override;

    virtual bool SetKey(const uint8_t *key, const size_t keylen) override;
    virtual bool Encrypt(const uint8_t *plain, uint8_t *cipher) override;
    virtual bool Decrypt(const uint8_t *cipher, uint8_t *plain) override;

private:
    enum_crypt_methods p_method;
    size_t p_blocksize;

    bool p_haskey;

    size_t p_keylen;
    uint8_t p_key[64];

    uint32_t p_k_len;
    uint32_t p_l_key[40];
    uint32_t p_s_key[4];

    uint32_t h_fun(const uint32_t x, const uint32_t key[]);
    void gen_mk_tab(uint32_t key[]);
    uint32_t *set_key(const uint32_t in_key[], const uint32_t key_len);
    void f_rnd(uint32_t i, uint32_t& t0, uint32_t& t1, uint32_t *blk);
    void encrypt(const uint32_t in_blk[4], uint32_t out_blk[4]);
    void i_rnd(uint32_t i, uint32_t& t0, uint32_t& t1, uint32_t *blk);
    void decrypt(const uint32_t in_blk[4], uint32_t out_blk[4]);
};

}
