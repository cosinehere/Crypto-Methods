#include "pch.h"
#include "CryptoMethodDefines.h"

#include "DES.h"
#include "TripDES.h"
#include "AES.h"
#include "RC5.h"
#include "RC6.h"
#include "Camellia.h"
#include "Blowfish.h"
#include "CBC.h"
#include "CFB.h"
#include "CTR.h"

#include <wincrypt.h>

NAMESPACE_BEGIN(CryptoMethods)

size_t Padding(uint8_t* buffer, size_t len, size_t blocksize)
{
	size_t left = blocksize - (len % blocksize);
	size_t lenret = len;
	if (left == 0) left += blocksize;
	for (size_t i = 0; i < left; ++i)
	{
		buffer[len + i] = static_cast<uint8_t>(left);
		lenret++;
	}

	return lenret;
}

void GenerateIV(uint8_t* iv, size_t ivlen)
{
	HCRYPTPROV crypt;
	CryptAcquireContext(&crypt, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(crypt, ivlen, iv);
	CryptReleaseContext(crypt, 0);
}

void MixBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix)
{
	GenerateIV(mix, 8);
	for (size_t i = 0; i < 4; ++i)
	{
		uint32_t pos = *reinterpret_cast<uint32_t*>(&mix[i]) % (4 + cipherlen / 8);
		uint64_t* cur = nullptr;
		uint64_t* post = nullptr;
		if (i < 2)
		{
			cur = reinterpret_cast<uint64_t*>(&key[i * 8]);
		}
		else
		{
			cur = reinterpret_cast<uint64_t*>(&iv[(i - 2) * 8]);
		}

		if (pos < 2)
		{
			post = reinterpret_cast<uint64_t*>(&key[pos * 8]);
		}
		else if (pos < 4)
		{
			post = reinterpret_cast<uint64_t*>(&iv[(pos - 2) * 8]);
		}
		else
		{
			post = reinterpret_cast<uint64_t*>(&cipher[(pos - 4) * 8]);
		}

		uint64_t tmp = *cur;
		*cur = *post;
		*post = tmp;
	}
}

void ScatterBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix)
{
	for (int i = 3; i >= 0; --i)
	{
		uint32_t pos = *reinterpret_cast<uint32_t*>(&mix[i]) % (4 + cipherlen / 8);
		uint64_t* cur = nullptr;
		uint64_t* post = nullptr;
		if (i < 2)
		{
			cur = reinterpret_cast<uint64_t*>(&key[i * 8]);
		}
		else
		{
			cur = reinterpret_cast<uint64_t*>(&iv[(i - 2) * 8]);
		}

		if (pos < 2)
		{
			post = reinterpret_cast<uint64_t*>(&key[pos * 8]);
		}
		else if (pos < 4)
		{
			post = reinterpret_cast<uint64_t*>(&iv[(pos - 2) * 8]);
		}
		else
		{
			post = reinterpret_cast<uint64_t*>(&cipher[(pos - 4) * 8]);
		}

		uint64_t tmp = *cur;
		*cur = *post;
		*post = tmp;
	}
}

void CreateAES(CipherBase*& base)
{
	base = new AES;
}

void ReleaseAES(CipherBase*& base)
{
	AES* aes = reinterpret_cast<AES*>(base);
	delete aes;
	base = nullptr;
}

void CreateRC5(CipherBase*& base)
{
	base = new RC5;
}

void ReleaseRC5(CipherBase*& base)
{
	RC5* rc5 = reinterpret_cast<RC5*>(base);
	delete rc5;
	base = nullptr;
}

void CreateRC6(CipherBase*& base)
{
	base = new RC6;
}

void ReleaseRC6(CipherBase*& base)
{
	RC6* rc6 = reinterpret_cast<RC6*>(base);
	delete rc6;
	base = nullptr;
}

void CreateDES(CipherBase*& base)
{
	base = new DES;
}

void ReleaseDES(CipherBase*& base)
{
	DES* des= reinterpret_cast<DES*>(base);
	delete des;
	base = nullptr;
}

void CreateTripDES(CipherBase*& base)
{
	base = new TripDES;
}

void ReleaseTripDES(CipherBase*& base)
{
	TripDES* tripdes = reinterpret_cast<TripDES*>(base);
	delete tripdes;
	base = nullptr;
}

void CreateCamellia(CipherBase*& base)
{
	base = new Camellia;
}

void ReleaseCamellia(CipherBase*& base)
{
	Camellia* camellia = reinterpret_cast<Camellia*>(base);
	delete camellia;
	base = nullptr;
}

void CreateBlowfish(CipherBase*& base)
{
	base = new Blowfish;
}

void ReleaseBlowfish(CipherBase*& base)
{
	Blowfish* blowfish = reinterpret_cast<Blowfish*>(base);
	delete blowfish;
	base = nullptr;
}

void AESCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CBC<AES> cbc;
	cbc.SetKey(key, keylen);
	uint8_t iv[16]; //= { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	GenerateIV(iv, 16);
	cbc.SetIV(iv, 16);

	uint8_t* temp = new uint8_t[inlen + 16];
	memcpy_s(temp, sizeof(uint8_t)*(inlen + 16), in, sizeof(uint8_t)*inlen);
	size_t templen = PKCS7(temp, inlen, 16);

	cbc.Encrypt(temp, templen, out, outlen);

	delete[] temp;
}

void AESCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CBC<AES> cbc;
	cbc.SetKey(key, keylen);
	uint8_t iv[16]; //= { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	GenerateIV(iv, 16);
	cbc.SetIV(iv, 16);
	cbc.Decrypt(in, inlen, out, outlen);
}

void AESCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CFB<AES> cfb;
	cfb.SetKey(key, keylen);
	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	//GenerateIV(iv, 16);
	cfb.SetIV(iv, 16);

	uint8_t* temp = new uint8_t[inlen];
	memcpy_s(temp, sizeof(uint8_t)*inlen, in, sizeof(uint8_t)*inlen);
	size_t templen = inlen;

	cfb.Encrypt(temp, templen, out, outlen);

	delete[] temp;
}

void AESCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CFB<AES> cfb;
	cfb.SetKey(key, keylen);
	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	//GenerateIV(iv, 16);
	cfb.SetIV(iv, 16);
	cfb.Decrypt(in, inlen, out, outlen);
}

void AESCTREncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CTR<AES> cbc;
	cbc.SetKey(key, keylen);
	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	//GenerateIV(iv, 16);
	cbc.SetIV(iv, 16);

	uint8_t* temp = new uint8_t[inlen];
	memcpy_s(temp, sizeof(uint8_t)*inlen, in, sizeof(uint8_t)*inlen);
	size_t templen = inlen;

	cbc.Encrypt(temp, templen, out, outlen);

	delete[] temp;
}

void AESCTRDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
{
	CTR<AES> cbc;
	cbc.SetKey(key, keylen);
	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
	//GenerateIV(iv, 16);
	cbc.SetIV(iv, 16);
	cbc.Decrypt(in, inlen, out, outlen);
}

NAMESPACE_END