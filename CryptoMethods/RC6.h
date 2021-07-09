#pragma once
#include "CryptoMethodDefines.h"

#include <cmath>

NAMESPACE_BEGIN(CryptoMethods)

#define RC6_WORD_W 32
#if RC6_WORD_W==32
typedef uint32_t rc6_word;

constexpr rc6_word c_rc6Pw = 0xb7e15163u;
constexpr rc6_word c_rc6Qw = 0x9e3779b9u;

constexpr size_t c_rc6lgw = 5;

#elif RC6_WORD_W==64
typedef uint64_t rc6_word;

constexpr rc6_word c_rc6Pw = 0xb7e151628aed2a6bull;
constexpr rc6_word c_rc6Qw = 0x9e3779b97f4a7c15ull;

constexpr size_t c_rc6lgw = 6;

#endif

constexpr size_t c_rc6w = RC6_WORD_W;	//length of a word in bits
constexpr size_t c_rc6r = 20;			//rounds to encrypt data
constexpr size_t c_rc6b = 16;			//length of the key in bytes

constexpr size_t c_rc6u = c_rc6w / 8;	//length of a word in bytes
constexpr size_t c_rc6t = 2 * (c_rc6r + 2);	//number of round subkeys
constexpr size_t c_rc6c = max(1, 8 * c_rc6b / c_rc6w);	//length of the key in words

class RC6 : public CipherBase
{
public:
	RC6();
	virtual ~RC6();

	virtual const size_t BlockSize() override;
	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) override;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) override;

private:
	size_t p_blocksize;

	bool p_haskey;

	uint8_t p_key[c_rc6b];

	rc6_word p_roundkey[c_rc6t];

	bool Setup();
};

NAMESPACE_END
