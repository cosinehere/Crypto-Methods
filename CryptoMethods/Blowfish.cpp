#include "pch.h"
#include "Blowfish.h"

NAMESPACE_BEGIN(CryptoMethods)

Blowfish::Blowfish()
{
	p_blocksize = c_blowfishblocksize;

	p_haskey = false;
}

Blowfish::~Blowfish()
{}

const size_t Blowfish::BlockSize()
{
	return p_blocksize;
}

bool Blowfish::SetKey(const uint8_t* key, const size_t keylen)
{
	if (key == nullptr || keylen < 8 || keylen>56)
	{
		return false;
	}

	p_keylen = keylen;
	memcpy(p_key, key, sizeof(uint8_t)*keylen);

	memcpy(p_S, c_InitS, sizeof(c_InitS));

	uint32_t k;
	for (int16_t i = 0, p = 0; i < 18; ++i)
	{
		k = 0;
		for (int16_t j = 0; j < 4; ++j)
		{
			k = (k << 8) | key[p];
			p = (p + 1) % p_keylen;
		}

		p_P[i] = c_InitP[i] ^ k;
	}

	uint32_t l = 0, r = 0;
	for (int16_t i = 0; i < 18; i += 2)
	{
		Encrypt(l, r);
		p_P[i] = l;
		p_P[i + 1] = r;
	}

	for (int16_t i = 0; i < 4; ++i)
	{
		for (int16_t j = 0; j < 256; j += 2)
		{
			Encrypt(l, r);
			p_S[i][j] = l;
			p_S[i][j + 1] = r;
		}
	}

	p_haskey = true;

	return true;
}

bool Blowfish::Encrypt(const uint8_t* plain, uint8_t* cipher)
{
	if (!p_haskey)
	{
		return false;
	}

	uint32_t L = plain[0] << 24 | plain[1] << 16 | plain[2] << 8 | plain[3];
	uint32_t R = plain[4] << 24 | plain[5] << 16 | plain[6] << 8 | plain[7];
	//uint32_t L = *reinterpret_cast<const uint32_t*>(plain);
	//uint32_t R = *reinterpret_cast<const uint32_t*>(&plain[c_blowfishblocksize >> 1]);

	Encrypt(L, R);

	cipher[0] = L >> 24;
	cipher[1] = L >> 16 & 0xff;
	cipher[2] = L >> 8 & 0xff;
	cipher[3] = L & 0xff;
	cipher[4] = R >> 24;
	cipher[5] = R >> 16 & 0xff;
	cipher[6] = R >> 8 & 0xff;
	cipher[7] = R & 0xff;
	//memcpy(cipher, &L, sizeof(uint32_t));
	//memcpy(&cipher[c_blowfishblocksize >> 1], &R, sizeof(uint32_t));

	return true;
}

bool Blowfish::Decrypt(const uint8_t* cipher, uint8_t* plain)
{
	if (!p_haskey)
	{
		return false;
	}

	uint32_t L = cipher[0] << 24 | cipher[1] << 16 | cipher[2] << 8 | cipher[3];
	uint32_t R = cipher[4] << 24 | cipher[5] << 16 | cipher[6] << 8 | cipher[7];
	//uint32_t L = *reinterpret_cast<const uint32_t*>(cipher);
	//uint32_t R = *reinterpret_cast<const uint32_t*>(&cipher[c_blowfishblocksize >> 1]);

	Decrypt(L, R);

	plain[0] = L >> 24;
	plain[1] = L >> 16 & 0xff;
	plain[2] = L >> 8 & 0xff;
	plain[3] = L & 0xff;
	plain[4] = R >> 24;
	plain[5] = R >> 16 & 0xff;
	plain[6] = R >> 8 & 0xff;
	plain[7] = R & 0xff;
	//memcpy(plain, &L, sizeof(uint32_t));
	//memcpy(&plain[c_blowfishblocksize >> 1], &R, sizeof(uint32_t));

	return true;
}

void Blowfish::Encrypt(uint32_t& L, uint32_t& R)
{
	for (int16_t r = 0; r < 16; ++r)
	{
		L = L ^ p_P[r];
		R = f(L) ^ R;

		uint32_t tmp = L;
		L = R;
		R = tmp;
	}

	uint32_t tmp = L;
	L = R;
	R = tmp;
	R = R ^ p_P[16];
	L = L ^ p_P[17];
}

void Blowfish::Decrypt(uint32_t& L, uint32_t& R)
{
	for (int16_t r = 17; r > 1; --r)
	{
		L = L ^ p_P[r];
		R = f(L) ^ R;

		uint32_t tmp = L;
		L = R;
		R = tmp;
	}

	uint32_t tmp = L;
	L = R;
	R = tmp;
	R = R ^ p_P[1];
	L = L ^ p_P[0];
}

NAMESPACE_END