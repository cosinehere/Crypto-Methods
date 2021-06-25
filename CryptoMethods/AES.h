#pragma once
#include "CryptoMethodDefines.h"

NAMESPACEBEGIN(CryptoMethods)

class AES : public CipherBase
{
public:
	AES();
	virtual ~AES();

	virtual bool SetMode(enum_crypt_mode mode) override;
	virtual bool UpdateKey(const uint8_t* key, const size_t keylen) override;
	virtual bool UpdateIV(const uint8_t* iv, const size_t ivlen) override;
	virtual bool UpdateData(const uint8_t* data, const size_t datalen) override;
	virtual bool Finally(uint8_t* out, size_t* outlen) override;
};

NAMESPACEEND
