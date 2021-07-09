#include "pch.h"
#include "DES.h"

#include <cstdio>

NAMESPACE_BEGIN(CryptoMethods)

DES::DES()
{
	p_blocksize = c_desblocksize;

	p_haskey = false;
}

DES::~DES()
{
}

const size_t DES::BlockSize()
{
	return p_blocksize;
}

bool DES::SetKey(const uint8_t* key, const size_t keylen)
{
	if (key == nullptr || keylen != c_deskeylen)
	{
		return false;
	}

	memcpy(p_key, key, sizeof(uint8_t)*keylen);

	bool bRet = KeySchedule();
	if (bRet)
	{
		p_haskey = true;
	}
	else
	{
		p_haskey = false;
	}

	return bRet;
}

bool DES::Encrypt(const uint8_t* plain, uint8_t* cipher)
{
	if (!p_haskey)
	{
		return false;
	}

	for (size_t i = 0; i < 64; ++i)
	{
		setbit(cipher, i, getbit(plain, IP[i] - 1));
	}

	uint32_t ln, rn, ln_1, rn_1;
	ln_1 = (cipher[0] << 0) | (cipher[1] << 8) | (cipher[2] << 16) | (cipher[3] << 24);
	rn_1 = (cipher[4] << 0) | (cipher[5] << 8) | (cipher[6] << 16) | (cipher[7] << 24);

	for (size_t i = 0; i < 16; ++i)
	{
		ln = rn_1;
		rn = ln_1 ^ Feistel(rn_1, p_subkey[i]);
		ln_1 = ln;
		rn_1 = rn;
	}

	uint64_t rnln = (static_cast<uint64_t>(ln) << 32) | rn;
	uint64_t fp;
	for (size_t i = 0; i < 64; ++i)
	{
		setbit(reinterpret_cast<uint8_t*>(&fp), i, getbit(reinterpret_cast<uint8_t*>(&rnln), FP[i] - 1));
	}

	for (size_t i = 0; i < 8; ++i)
	{
		cipher[i] = (fp >> (i * 8)) & 0xff;
	}

	return true;
}

bool DES::Decrypt(const uint8_t* cipher, uint8_t* plain)
{
	if (!p_haskey)
	{
		return false;
	}

	for (size_t i = 64; i > 0; --i)
	{
		setbit(plain, i - 1, getbit(cipher, IP[i - 1] - 1));
	}

	uint32_t ln, rn, ln_1, rn_1;
	rn = (plain[4] << 0) | (plain[5] << 8) | (plain[6] << 16) | (plain[7] << 24);
	ln = (plain[0] << 0) | (plain[1] << 8) | (plain[2] << 16) | (plain[3] << 24);

	for (size_t i = 16; i > 0; --i)
	{
		rn_1 = rn;
		ln_1 = ln;

		rn = ln_1 ^ Feistel(rn_1, p_subkey[i - 1]);
		ln = rn_1;
	}

	uint64_t rnln = (static_cast<uint64_t>(ln) << 32) | rn;
	uint64_t fp;
	for (size_t i = 64; i > 0; --i)
	{
		setbit(reinterpret_cast<uint8_t*>(&fp), i - 1, getbit(reinterpret_cast<uint8_t*>(&rnln), FP[i - 1] - 1));
	}

	for (size_t i = 0; i < 8; ++i)
	{
		plain[i] = (fp >> (i * 8)) & 0xff;
	}


	return false;
}

bool DES::KeySchedule()
{
	uint8_t key_p[7] = { 0 };

	for (size_t i = 0; i < 56; ++i)
	{
		setbit(key_p, i, getbit(p_key, PC_1[i] - 1));
	}

	auto key_shift = [](uint8_t key[])->void {
		bool a = getbit(key, 0);
		bool b = getbit(key, 28);
		for (size_t i = 0; i < 55; ++i)
			setbit(key, i, getbit(key, i + 1));
		setbit(key, 27, a);
		setbit(key, 55, b);
	};

	for (size_t i = 0; i < 16; ++i)
	{
		key_shift(key_p);
		if (i != 0 && i != 1 && i != 8 && i != 15) key_shift(key_p);
		for (size_t j = 0; j < 48; ++j)
		{
			setbit(&p_subkey[i][0], j, getbit(key_p, PC_2[j] - 1));
		}
	}

	return true;
}

uint32_t DES::Feistel(const uint32_t rn_1, const uint8_t* k)
{
	uint8_t e[6];
	for (size_t i = 0; i < 48; ++i)
	{
		setbit(e, i, getbit(reinterpret_cast<const uint8_t*>(&rn_1), E[i] - 1));
	}

	for (size_t i = 0; i < 6; ++i)
	{
		e[i] ^= k[i];
	}

	uint32_t val = 0;
	for (size_t i = 0; i < 8; ++i)
	{
		uint8_t Sbox_value = S[i][(getbit(e, 6 * i + 0) << 5) |
									(getbit(e, 6 * i + 5) << 4) |
									(getbit(e, 6 * i + 1) << 3) |
									(getbit(e, 6 * i + 2) << 2) |
									(getbit(e, 6 * i + 3) << 1) |
									(getbit(e, 6 * i + 4) << 0)];
		setbit(reinterpret_cast<uint8_t*>(&val), i * 4 + 0, getbit(&Sbox_value, 4));
		setbit(reinterpret_cast<uint8_t*>(&val), i * 4 + 1, getbit(&Sbox_value, 5));
		setbit(reinterpret_cast<uint8_t*>(&val), i * 4 + 2, getbit(&Sbox_value, 6));
		setbit(reinterpret_cast<uint8_t*>(&val), i * 4 + 3, getbit(&Sbox_value, 7));
	}

	uint32_t ret;
	for (size_t i = 0; i < 32; ++i)
	{
		setbit(reinterpret_cast<uint8_t*>(&ret), i, getbit(reinterpret_cast<uint8_t*>(&val), P[i] - 1));
	}

	return ret;
}

NAMESPACE_END
