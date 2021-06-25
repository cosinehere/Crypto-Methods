#include "pch.h"
#include "AES.h"

NAMESPACEBEGIN(CryptoMethods)

AES::AES()
{}

AES::~AES()
{}

bool AES::SetMode(enum_crypt_mode mode)
{
	return false;
}

bool AES::UpdateKey(const uint8_t* key, const size_t keylen)
{
	return false;
};

bool AES::UpdateIV(const uint8_t* iv, const size_t ivlen)
{
	return false;
};

bool AES::UpdateData(const uint8_t* data, const size_t datalen)
{
	return false;
};

bool AES::Finally(uint8_t* out, size_t* outlen)
{
	return false;
};

NAMESPACEEND
