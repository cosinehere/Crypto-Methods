#include "pch.h"
#include "RC5.h"

NAMESPACE_BEGIN(CryptoMethods)

RC5::RC5()
{
	p_blocksize = 8;

	p_haskey = false;
}

RC5::~RC5()
{}

const size_t RC5::BlockSize()
{
	return p_blocksize;
}

bool RC5::SetKey(const uint8_t * key, const size_t keylen)
{
	if (key == nullptr || keylen != c_rc5b)
	{
		return false;
	}

	memcpy(p_key, key, sizeof(uint8_t)*c_rc5b);

	bool bRet = Setup();
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

bool RC5::Encrypt(const uint8_t * plain, uint8_t * cipher)
{
	if (!p_haskey)
	{
		return false;
	}

	rc5_word A = *reinterpret_cast<rc5_word*>(const_cast<uint8_t*>(plain)) + p_roundkey[0];
	rc5_word B = *reinterpret_cast<rc5_word*>(const_cast<uint8_t*>(&plain[4])) + p_roundkey[1];
	for (size_t i = 1; i <= c_rc5r; ++i)
	{
		A = l_rot<rc5_word>(A^B, B & 0x1f) + p_roundkey[i << 1];
		B = l_rot<rc5_word>(B^A, A & 0x1f) + p_roundkey[(i << 1) + 1];
	}

	rc5_word* c0 = reinterpret_cast<rc5_word*>(cipher);
	rc5_word* c1 = reinterpret_cast<rc5_word*>(&cipher[4]);

	*c0 = A;
	*c1 = B;

	return true;
}

bool RC5::Decrypt(const uint8_t * cipher, uint8_t * plain)
{
	if (!p_haskey)
	{
		return false;
	}

	rc5_word B = *reinterpret_cast<rc5_word*>(const_cast<uint8_t*>(&cipher[4]));
	rc5_word A = *reinterpret_cast<rc5_word*>(const_cast<uint8_t*>(cipher));
	for (size_t i = c_rc5r; i > 0; --i)
	{
		B = r_rot<rc5_word>(B - p_roundkey[(i << 1) + 1], A & 0x1f) ^ A;
		A = r_rot<rc5_word>(A - p_roundkey[i << 1], B & 0x1f) ^ B;
	}

	rc5_word* p1 = reinterpret_cast<rc5_word*>(&plain[4]);
	rc5_word* p0 = reinterpret_cast<rc5_word*>(plain);

	*p1 = B - p_roundkey[1];
	*p0 = A - p_roundkey[0];

	return true;
}

bool RC5::Setup()
{
	rc5_word L[c_rc5c] = { 0 };
	L[c_rc5c - 1] = 0;
	for (size_t i = c_rc5b - 1; i != -1; --i)
	{
		L[i / c_rc5u] = (L[i / c_rc5u] << 8) + p_key[i];
	}

	p_roundkey[0] = c_rc5Pw;
	for (size_t i = 1; i < c_rc5t; ++i)
	{
		p_roundkey[i] = p_roundkey[i - 1] + c_rc5Qw;
	}

	rc5_word A = 0, B = 0;
	for (size_t i = 0, j = 0, k = 0; k < 3 * c_rc5t; ++k, i = (i + 1) % c_rc5t, j = (j + 1) % c_rc5c)
	{
		A = p_roundkey[i] = l_rot<rc5_word>(p_roundkey[i] + A + B, 3);
		B = L[j] = l_rot<rc5_word>(L[j] + A + B, (A + B) & 0x1f);
	}

	return true;
}

NAMESPACE_END