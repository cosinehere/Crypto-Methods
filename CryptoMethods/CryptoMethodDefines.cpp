#include "pch.h"
#include "CryptoMethodDefines.h"

#include "AES.h"
#include "CBC.h"
#include "CFB.h"
#include "CTR.h"

#include <wincrypt.h>

NAMESPACEBEGIN(CryptoMethods)

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

void CreateAES(CipherBase*& base)
{
	base = new AES;
}

void ReleaseAES(CipherBase*& base)
{
	delete base;
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

NAMESPACEEND