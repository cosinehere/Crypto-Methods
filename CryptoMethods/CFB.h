#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

template<class CIPHER>
class CFB : public CipherModeBase
{
public:
	CFB();
	virtual ~CFB();

	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool SetIV(const uint8_t* iv, const size_t ivlen) override;

	virtual bool Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) override;
	virtual bool Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) override;

private:
	CIPHER p_cipher;
	size_t p_blocksize;

	uint8_t* p_iv;
	size_t p_ivlen;
};

template<class CIPHER>
CFB<CIPHER>::CFB()
{
	p_blocksize = p_cipher.BlockSize();

	p_iv = nullptr;
	p_ivlen = 0;
}

template<class CIPHER>
CFB<CIPHER>::~CFB()
{
	if (p_iv != nullptr)
	{
		delete[] p_iv;
	}
}

template<class CIPHER>
bool CFB<CIPHER>::SetKey(const uint8_t* key, const size_t keylen)
{
	return p_cipher.SetKey(key, keylen);
}

template<class CIPHER>
bool CFB<CIPHER>::SetIV(const uint8_t* iv, const size_t ivlen)
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
	memcpy_s(p_iv, sizeof(uint8_t)*ivlen, iv, sizeof(uint8_t)*ivlen);

	return true;
}

template<class CIPHER>
bool CFB<CIPHER>::Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += p_blocksize;
		if (i == 0)
		{
			p_cipher.Encrypt(p_iv, temp);
		}
		else
		{
			p_cipher.Encrypt(&out[i - p_blocksize], temp);
		}

		for (size_t j = 0; j < p_blocksize; ++j)
		{
			out[i + j] = temp[j] ^ in[i + j];
		}
	}
	delete[] temp;

	return true;
}

template<class CIPHER>
bool CFB<CIPHER>::Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += p_blocksize;
		if (i == 0)
		{
			p_cipher.Encrypt(p_iv, temp);
		}
		else
		{
			p_cipher.Encrypt(&out[i - p_blocksize], temp);
		}

		for (size_t j = 0; j < p_blocksize; ++j)
		{
			out[i + j] = temp[j] ^ in[i + j];
		}
	}
	delete[] temp;

	return true;
}

NAMESPACE_END
