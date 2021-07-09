#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

template<class CIPHER>
class CTR :	public CipherModeBase
{
public:
	CTR();
	virtual ~CTR();

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
CTR<CIPHER>::CTR()
{
	p_blocksize = p_cipher.BlockSize();

	p_iv = nullptr;
	p_ivlen = 0;
}

template<class CIPHER>
CTR<CIPHER>::~CTR()
{
	if (p_iv != nullptr)
	{
		delete[] p_iv;
	}
}

template<class CIPHER>
bool CTR<CIPHER>::SetKey(const uint8_t* key, const size_t keylen)
{
	return p_cipher.SetKey(key, keylen);
}

template<class CIPHER>
bool CTR<CIPHER>::SetIV(const uint8_t* iv, const size_t ivlen)
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

template<class CIPHER>
bool CTR<CIPHER>::Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	uint8_t* counter = new uint8_t[p_blocksize];
	memcpy(counter, p_iv, sizeof(uint8_t)*p_blocksize);
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += (inlen - i > p_blocksize) ? p_blocksize : (inlen - i);
		p_cipher.Encrypt(counter, temp);
		
		for (size_t j = 0; j < p_blocksize; ++j)
		{
			out[i + j] = temp[j] ^ in[i + j];
		}

		uint32_t cnt = (uint32_t)counter[p_blocksize - 1] | ((uint32_t)counter[p_blocksize - 2] << 8) |
						((uint32_t)counter[p_blocksize - 3] << 16) | ((uint32_t)counter[p_blocksize - 4] << 24);
		cnt++;
		counter[p_blocksize - 1] = cnt & 0xff;
		counter[p_blocksize - 2] = (cnt >> 8) & 0xff;
		counter[p_blocksize - 3] = (cnt >> 16) & 0xff;
		counter[p_blocksize - 4] = (cnt >> 24) & 0xff;
	}
	delete[] temp;
	delete[] counter;

	return true;
}

template<class CIPHER>
bool CTR<CIPHER>::Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	uint8_t* temp = new uint8_t[p_blocksize];
	uint8_t* counter = new uint8_t[p_blocksize];
	memcpy(counter, p_iv, sizeof(uint8_t)*p_blocksize);
	outlen = 0;
	for (size_t i = 0; i < inlen; i += p_blocksize)
	{
		outlen += p_blocksize;
		p_cipher.Encrypt(counter, temp);

		for (size_t j = 0; j < p_blocksize; ++j)
		{
			out[i + j] = temp[j] ^ in[i + j];
		}

		uint32_t cnt = (uint32_t)counter[p_blocksize - 1] | ((uint32_t)counter[p_blocksize - 2] << 8) |
			((uint32_t)counter[p_blocksize - 3] << 16) | ((uint32_t)counter[p_blocksize - 4] << 24);
		cnt++;
		counter[p_blocksize - 1] = cnt & 0xff;
		counter[p_blocksize - 2] = (cnt >> 8) & 0xff;
		counter[p_blocksize - 3] = (cnt >> 16) & 0xff;
		counter[p_blocksize - 4] = (cnt >> 24) & 0xff;
	}
	delete[] temp;
	delete[] counter;

	return true;
}

NAMESPACE_END
