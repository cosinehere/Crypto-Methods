#pragma once
#include "CryptoMethodDefines.h"

#include "DES.h"

NAMESPACE_BEGIN(CryptoMethods)

class TripDES : public CipherBase
{
public:
	TripDES();
	virtual ~TripDES();

	virtual const size_t BlockSize() override;
	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) override;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) override;

private:
	size_t p_blocksize;

	bool p_haskey;

	DES p_des1, p_des2, p_des3;
};

NAMESPACE_END
