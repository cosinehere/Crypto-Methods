#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

class CBC : public CipherModeBase
{
public:
	CBC(CipherBase* base);
	virtual ~CBC();

	virtual const enum_crypt_modes CryptMode() { return p_mode; }

	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool SetIV(const uint8_t* iv, const size_t ivlen) override;

	virtual bool Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) override;
	virtual bool Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) override;

#ifndef CXX11_NOT_SUPPORT
private:
	CBC(const CBC&) = delete;
	CBC(const CBC&&) = delete;
	CBC& operator=(const CBC&) = delete;
	CBC& operator=(const CBC&&) = delete;
#endif	// CXX11_NOT_SUPPORT

private:
	enum_crypt_modes p_mode;

	CipherBase* p_cipher;
	size_t p_blocksize;

	uint8_t* p_iv;
	size_t p_ivlen;
};

CBC::CBC(CipherBase* base)
{
	p_mode = enum_crypt_mode_cbc;

	p_cipher = base;
	p_blocksize = p_cipher->BlockSize();

	p_iv = new uint8_t[p_blocksize];
	p_ivlen = p_blocksize;
}

CBC::~CBC()
{
	if (p_iv != nullptr)
	{
		delete[] p_iv;
	}
}

bool CBC::SetKey(const uint8_t* key, const size_t keylen)
{
	return p_cipher->SetKey(key, keylen);
}

bool CBC::SetIV(const uint8_t* iv, const size_t ivlen)
{
	if (iv == nullptr || ivlen == 0)
	{
		return false;
	}

	if (p_iv != nullptr)
	{
		delete[] p_iv;
	}

	p_iv = new uint8_t[ivlen];
	memcpy(p_iv, iv, sizeof(uint8_t)*ivlen);

	return true;
}

bool CBC::Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += p_blocksize;
		if (i == 0)
		{
			for (size_t j = 0; j < p_blocksize; ++j)
			{
				temp[j] = in[j] ^ p_iv[j];
			}
		}
		else
		{
			for (size_t j = 0; j < p_blocksize; ++j)
			{
				temp[j] = out[i - p_blocksize + j] ^ in[i + j];
			}
		}

		p_cipher->Encrypt(temp, &out[i]);
	}
	delete[] temp;

	return true;
}

bool CBC::Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += p_blocksize;
		p_cipher->Decrypt(&in[i], temp);
		if (i == 0)
		{
			for (size_t j = 0; j < p_blocksize; ++j)
			{
				out[j] = temp[j] ^ p_iv[j];
			}
		}
		else
		{
			for (size_t j = 0; j < p_blocksize; ++j)
			{
				out[i + j] = temp[j] ^ in[i - p_blocksize + j];
			}
		}
	}
	delete[] temp;

	return true;
}

NAMESPACE_END
