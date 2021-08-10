#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

constexpr size_t c_aesblocksize = 16;

constexpr uint8_t Rcon[][4] = {
    {0x01u, 0x00u, 0x00u, 0x00u}, {0x02u, 0x00u, 0x00u, 0x00u},
    {0x04u, 0x00u, 0x00u, 0x00u}, {0x08u, 0x00u, 0x00u, 0x00u},
    {0x10u, 0x00u, 0x00u, 0x00u}, {0x20u, 0x00u, 0x00u, 0x00u},
    {0x40u, 0x00u, 0x00u, 0x00u}, {0x80u, 0x00u, 0x00u, 0x00u},
    {0x1bu, 0x00u, 0x00u, 0x00u}, {0x36u, 0x00u, 0x00u, 0x00u}};

constexpr uint8_t SBox[256] = {
    0x63u, 0x7cu, 0x77u, 0x7bu, 0xf2u, 0x6bu, 0x6fu, 0xc5u, 0x30u, 0x01u, 0x67u,
    0x2bu, 0xfeu, 0xd7u, 0xabu, 0x76u, 0xcau, 0x82u, 0xc9u, 0x7du, 0xfau, 0x59u,
    0x47u, 0xf0u, 0xadu, 0xd4u, 0xa2u, 0xafu, 0x9cu, 0xa4u, 0x72u, 0xc0u, 0xb7u,
    0xfdu, 0x93u, 0x26u, 0x36u, 0x3fu, 0xf7u, 0xccu, 0x34u, 0xa5u, 0xe5u, 0xf1u,
    0x71u, 0xd8u, 0x31u, 0x15u, 0x04u, 0xc7u, 0x23u, 0xc3u, 0x18u, 0x96u, 0x05u,
    0x9au, 0x07u, 0x12u, 0x80u, 0xe2u, 0xebu, 0x27u, 0xb2u, 0x75u, 0x09u, 0x83u,
    0x2cu, 0x1au, 0x1bu, 0x6eu, 0x5au, 0xa0u, 0x52u, 0x3bu, 0xd6u, 0xb3u, 0x29u,
    0xe3u, 0x2fu, 0x84u, 0x53u, 0xd1u, 0x00u, 0xedu, 0x20u, 0xfcu, 0xb1u, 0x5bu,
    0x6au, 0xcbu, 0xbeu, 0x39u, 0x4au, 0x4cu, 0x58u, 0xcfu, 0xd0u, 0xefu, 0xaau,
    0xfbu, 0x43u, 0x4du, 0x33u, 0x85u, 0x45u, 0xf9u, 0x02u, 0x7fu, 0x50u, 0x3cu,
    0x9fu, 0xa8u, 0x51u, 0xa3u, 0x40u, 0x8fu, 0x92u, 0x9du, 0x38u, 0xf5u, 0xbcu,
    0xb6u, 0xdau, 0x21u, 0x10u, 0xffu, 0xf3u, 0xd2u, 0xcdu, 0x0cu, 0x13u, 0xecu,
    0x5fu, 0x97u, 0x44u, 0x17u, 0xc4u, 0xa7u, 0x7eu, 0x3du, 0x64u, 0x5du, 0x19u,
    0x73u, 0x60u, 0x81u, 0x4fu, 0xdcu, 0x22u, 0x2au, 0x90u, 0x88u, 0x46u, 0xeeu,
    0xb8u, 0x14u, 0xdeu, 0x5eu, 0x0bu, 0xdbu, 0xe0u, 0x32u, 0x3au, 0x0au, 0x49u,
    0x06u, 0x24u, 0x5cu, 0xc2u, 0xd3u, 0xacu, 0x62u, 0x91u, 0x95u, 0xe4u, 0x79u,
    0xe7u, 0xc8u, 0x37u, 0x6du, 0x8du, 0xd5u, 0x4eu, 0xa9u, 0x6cu, 0x56u, 0xf4u,
    0xeau, 0x65u, 0x7au, 0xaeu, 0x08u, 0xbau, 0x78u, 0x25u, 0x2eu, 0x1cu, 0xa6u,
    0xb4u, 0xc6u, 0xe8u, 0xddu, 0x74u, 0x1fu, 0x4bu, 0xbdu, 0x8bu, 0x8au, 0x70u,
    0x3eu, 0xb5u, 0x66u, 0x48u, 0x03u, 0xf6u, 0x0eu, 0x61u, 0x35u, 0x57u, 0xb9u,
    0x86u, 0xc1u, 0x1du, 0x9eu, 0xe1u, 0xf8u, 0x98u, 0x11u, 0x69u, 0xd9u, 0x8eu,
    0x94u, 0x9bu, 0x1eu, 0x87u, 0xe9u, 0xceu, 0x55u, 0x28u, 0xdfu, 0x8cu, 0xa1u,
    0x89u, 0x0du, 0xbfu, 0xe6u, 0x42u, 0x68u, 0x41u, 0x99u, 0x2du, 0x0fu, 0xb0u,
    0x54u, 0xbbu, 0x16u};

constexpr uint8_t RSBox[256] = {
    0x52u, 0x09u, 0x6au, 0xd5u, 0x30u, 0x36u, 0xa5u, 0x38u, 0xbfu, 0x40u, 0xa3u,
    0x9eu, 0x81u, 0xf3u, 0xd7u, 0xfbu, 0x7cu, 0xe3u, 0x39u, 0x82u, 0x9bu, 0x2fu,
    0xffu, 0x87u, 0x34u, 0x8eu, 0x43u, 0x44u, 0xc4u, 0xdeu, 0xe9u, 0xcbu, 0x54u,
    0x7bu, 0x94u, 0x32u, 0xa6u, 0xc2u, 0x23u, 0x3du, 0xeeu, 0x4cu, 0x95u, 0x0bu,
    0x42u, 0xfau, 0xc3u, 0x4eu, 0x08u, 0x2eu, 0xa1u, 0x66u, 0x28u, 0xd9u, 0x24u,
    0xb2u, 0x76u, 0x5bu, 0xa2u, 0x49u, 0x6du, 0x8bu, 0xd1u, 0x25u, 0x72u, 0xf8u,
    0xf6u, 0x64u, 0x86u, 0x68u, 0x98u, 0x16u, 0xd4u, 0xa4u, 0x5cu, 0xccu, 0x5du,
    0x65u, 0xb6u, 0x92u, 0x6cu, 0x70u, 0x48u, 0x50u, 0xfdu, 0xedu, 0xb9u, 0xdau,
    0x5eu, 0x15u, 0x46u, 0x57u, 0xa7u, 0x8du, 0x9du, 0x84u, 0x90u, 0xd8u, 0xabu,
    0x00u, 0x8cu, 0xbcu, 0xd3u, 0x0au, 0xf7u, 0xe4u, 0x58u, 0x05u, 0xb8u, 0xb3u,
    0x45u, 0x06u, 0xd0u, 0x2cu, 0x1eu, 0x8fu, 0xcau, 0x3fu, 0x0fu, 0x02u, 0xc1u,
    0xafu, 0xbdu, 0x03u, 0x01u, 0x13u, 0x8au, 0x6bu, 0x3au, 0x91u, 0x11u, 0x41u,
    0x4fu, 0x67u, 0xdcu, 0xeau, 0x97u, 0xf2u, 0xcfu, 0xceu, 0xf0u, 0xb4u, 0xe6u,
    0x73u, 0x96u, 0xacu, 0x74u, 0x22u, 0xe7u, 0xadu, 0x35u, 0x85u, 0xe2u, 0xf9u,
    0x37u, 0xe8u, 0x1cu, 0x75u, 0xdfu, 0x6eu, 0x47u, 0xf1u, 0x1au, 0x71u, 0x1du,
    0x29u, 0xc5u, 0x89u, 0x6fu, 0xb7u, 0x62u, 0x0eu, 0xaau, 0x18u, 0xbeu, 0x1bu,
    0xfcu, 0x56u, 0x3eu, 0x4bu, 0xc6u, 0xd2u, 0x79u, 0x20u, 0x9au, 0xdbu, 0xc0u,
    0xfeu, 0x78u, 0xcdu, 0x5au, 0xf4u, 0x1fu, 0xddu, 0xa8u, 0x33u, 0x88u, 0x07u,
    0xc7u, 0x31u, 0xb1u, 0x12u, 0x10u, 0x59u, 0x27u, 0x80u, 0xecu, 0x5fu, 0x60u,
    0x51u, 0x7fu, 0xa9u, 0x19u, 0xb5u, 0x4au, 0x0du, 0x2du, 0xe5u, 0x7au, 0x9fu,
    0x93u, 0xc9u, 0x9cu, 0xefu, 0xa0u, 0xe0u, 0x3bu, 0x4du, 0xaeu, 0x2au, 0xf5u,
    0xb0u, 0xc8u, 0xebu, 0xbbu, 0x3cu, 0x83u, 0x53u, 0x99u, 0x61u, 0x17u, 0x2bu,
    0x04u, 0x7eu, 0xbau, 0x77u, 0xd6u, 0x26u, 0xe1u, 0x69u, 0x14u, 0x63u, 0x55u,
    0x21u, 0x0cu, 0x7du};

constexpr uint8_t gfpower[] = {
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u, 0x1du, 0x3au, 0x74u,
    0xe8u, 0xcdu, 0x87u, 0x13u, 0x26u, 0x4cu, 0x98u, 0x2du, 0x5au, 0xb4u, 0x75u,
    0xeau, 0xc9u, 0x8fu, 0x03u, 0x06u, 0x0cu, 0x18u, 0x30u, 0x60u, 0xc0u, 0x9du,
    0x27u, 0x4eu, 0x9cu, 0x25u, 0x4au, 0x94u, 0x35u, 0x6au, 0xd4u, 0xb5u, 0x77u,
    0xeeu, 0xc1u, 0x9fu, 0x23u, 0x46u, 0x8cu, 0x05u, 0x0au, 0x14u, 0x28u, 0x50u,
    0xa0u, 0x5du, 0xbau, 0x69u, 0xd2u, 0xb9u, 0x6fu, 0xdeu, 0xa1u, 0x5fu, 0xbeu,
    0x61u, 0xc2u, 0x99u, 0x2fu, 0x5eu, 0xbcu, 0x65u, 0xcau, 0x89u, 0x0fu, 0x1eu,
    0x3cu, 0x78u, 0xf0u, 0xfdu, 0xe7u, 0xd3u, 0xbbu, 0x6bu, 0xd6u, 0xb1u, 0x7fu,
    0xfeu, 0xe1u, 0xdfu, 0xa3u, 0x5bu, 0xb6u, 0x71u, 0xe2u, 0xd9u, 0xafu, 0x43u,
    0x86u, 0x11u, 0x22u, 0x44u, 0x88u, 0x0du, 0x1au, 0x34u, 0x68u, 0xd0u, 0xbdu,
    0x67u, 0xceu, 0x81u, 0x1fu, 0x3eu, 0x7cu, 0xf8u, 0xedu, 0xc7u, 0x93u, 0x3bu,
    0x76u, 0xecu, 0xc5u, 0x97u, 0x33u, 0x66u, 0xccu, 0x85u, 0x17u, 0x2eu, 0x5cu,
    0xb8u, 0x6du, 0xdau, 0xa9u, 0x4fu, 0x9eu, 0x21u, 0x42u, 0x84u, 0x15u, 0x2au,
    0x54u, 0xa8u, 0x4du, 0x9au, 0x29u, 0x52u, 0xa4u, 0x55u, 0xaau, 0x49u, 0x92u,
    0x39u, 0x72u, 0xe4u, 0xd5u, 0xb7u, 0x73u, 0xe6u, 0xd1u, 0xbfu, 0x63u, 0xc6u,
    0x91u, 0x3fu, 0x7eu, 0xfcu, 0xe5u, 0xd7u, 0xb3u, 0x7bu, 0xf6u, 0xf1u, 0xffu,
    0xe3u, 0xdbu, 0xabu, 0x4bu, 0x96u, 0x31u, 0x62u, 0xc4u, 0x95u, 0x37u, 0x6eu,
    0xdcu, 0xa5u, 0x57u, 0xaeu, 0x41u, 0x82u, 0x19u, 0x32u, 0x64u, 0xc8u, 0x8du,
    0x07u, 0x0eu, 0x1cu, 0x38u, 0x70u, 0xe0u, 0xddu, 0xa7u, 0x53u, 0xa6u, 0x51u,
    0xa2u, 0x59u, 0xb2u, 0x79u, 0xf2u, 0xf9u, 0xefu, 0xc3u, 0x9bu, 0x2bu, 0x56u,
    0xacu, 0x45u, 0x8au, 0x09u, 0x12u, 0x24u, 0x48u, 0x90u, 0x3du, 0x7au, 0xf4u,
    0xf5u, 0xf7u, 0xf3u, 0xfbu, 0xebu, 0xcbu, 0x8bu, 0x0bu, 0x16u, 0x2cu, 0x58u,
    0xb0u, 0x7du, 0xfau, 0xe9u, 0xcfu, 0x83u, 0x1bu, 0x36u, 0x6cu, 0xd8u, 0xadu,
    0x47u, 0x8eu, 0x01u};

constexpr uint8_t gflog[] = {
    0x00u, 0x00u, 0x01u, 0x19u, 0x02u, 0x32u, 0x1au, 0xc6u, 0x03u, 0xdfu, 0x33u,
    0xeeu, 0x1bu, 0x68u, 0xc7u, 0x4bu, 0x04u, 0x64u, 0xe0u, 0x0eu, 0x34u, 0x8du,
    0xefu, 0x81u, 0x1cu, 0xc1u, 0x69u, 0xf8u, 0xc8u, 0x08u, 0x4cu, 0x71u, 0x05u,
    0x8au, 0x65u, 0x2fu, 0xe1u, 0x24u, 0x0fu, 0x21u, 0x35u, 0x93u, 0x8eu, 0xdau,
    0xf0u, 0x12u, 0x82u, 0x45u, 0x1du, 0xb5u, 0xc2u, 0x7du, 0x6au, 0x27u, 0xf9u,
    0xb9u, 0xc9u, 0x9au, 0x09u, 0x78u, 0x4du, 0xe4u, 0x72u, 0xa6u, 0x06u, 0xbfu,
    0x8bu, 0x62u, 0x66u, 0xddu, 0x30u, 0xfdu, 0xe2u, 0x98u, 0x25u, 0xb3u, 0x10u,
    0x91u, 0x22u, 0x88u, 0x36u, 0xd0u, 0x94u, 0xceu, 0x8fu, 0x96u, 0xdbu, 0xbdu,
    0xf1u, 0xd2u, 0x13u, 0x5cu, 0x83u, 0x38u, 0x46u, 0x40u, 0x1eu, 0x42u, 0xb6u,
    0xa3u, 0xc3u, 0x48u, 0x7eu, 0x6eu, 0x6bu, 0x3au, 0x28u, 0x54u, 0xfau, 0x85u,
    0xbau, 0x3du, 0xcau, 0x5eu, 0x9bu, 0x9fu, 0x0au, 0x15u, 0x79u, 0x2bu, 0x4eu,
    0xd4u, 0xe5u, 0xacu, 0x73u, 0xf3u, 0xa7u, 0x57u, 0x07u, 0x70u, 0xc0u, 0xf7u,
    0x8cu, 0x80u, 0x63u, 0x0du, 0x67u, 0x4au, 0xdeu, 0xedu, 0x31u, 0xc5u, 0xfeu,
    0x18u, 0xe3u, 0xa5u, 0x99u, 0x77u, 0x26u, 0xb8u, 0xb4u, 0x7cu, 0x11u, 0x44u,
    0x92u, 0xd9u, 0x23u, 0x20u, 0x89u, 0x2eu, 0x37u, 0x3fu, 0xd1u, 0x5bu, 0x95u,
    0xbcu, 0xcfu, 0xcdu, 0x90u, 0x87u, 0x97u, 0xb2u, 0xdcu, 0xfcu, 0xbeu, 0x61u,
    0xf2u, 0x56u, 0xd3u, 0xabu, 0x14u, 0x2au, 0x5du, 0x9eu, 0x84u, 0x3cu, 0x39u,
    0x53u, 0x47u, 0x6du, 0x41u, 0xa2u, 0x1fu, 0x2du, 0x43u, 0xd8u, 0xb7u, 0x7bu,
    0xa4u, 0x76u, 0xc4u, 0x17u, 0x49u, 0xecu, 0x7fu, 0x0cu, 0x6fu, 0xf6u, 0x6cu,
    0xa1u, 0x3bu, 0x52u, 0x29u, 0x9du, 0x55u, 0xaau, 0xfbu, 0x60u, 0x86u, 0xb1u,
    0xbbu, 0xccu, 0x3eu, 0x5au, 0xcbu, 0x59u, 0x5fu, 0xb0u, 0x9cu, 0xa9u, 0xa0u,
    0x51u, 0x0bu, 0xf5u, 0x16u, 0xebu, 0x7au, 0x75u, 0x2cu, 0xd7u, 0x4fu, 0xaeu,
    0xd5u, 0xe9u, 0xe6u, 0xe7u, 0xadu, 0xe8u, 0x74u, 0xd6u, 0xf4u, 0xeau, 0xa8u,
    0x50u, 0x58u, 0xafu};

class AES : public CipherBase {
   public:
    AES();
    virtual ~AES();

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

    uint8_t p_key[32];
    size_t p_keylen;
    size_t p_rounds;

    uint8_t p_roundkey[240];
    size_t p_roundkeylen;

    bool KeyExpand();
};

NAMESPACE_END
