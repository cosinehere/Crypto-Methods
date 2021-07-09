#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

#ifdef  __cplusplus
extern "C" {
#endif

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

	typedef uint32_t KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];

	bool Camellia_Ekeygen(const size_t keyBitLength, const uint8_t *rawKey, KEY_TABLE_TYPE keyTable);

	bool Camellia_EncryptBlock(const size_t keyBitLength, const uint8_t *plaintext, const KEY_TABLE_TYPE keyTable, uint8_t *cipherText);

	bool Camellia_DecryptBlock(const size_t keyBitLength, const uint8_t *cipherText, const KEY_TABLE_TYPE keyTable, uint8_t *plaintext);

#ifdef  __cplusplus
}
#endif

class Camellia : public CipherBase
{
public:
	Camellia();
	virtual ~Camellia();

	virtual const size_t BlockSize() override;
	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) override;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) override;

private:
	size_t p_blocksize;

	bool p_haskey;

	uint8_t p_key[256];
	size_t p_keylen;

	KEY_TABLE_TYPE p_keytable;
};

NAMESPACE_END
