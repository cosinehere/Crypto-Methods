#include "pch.h"
#include "CryptoMethodDefines.h"

#include "DES.h"
#include "TripDES.h"
#include "AES.h"
#include "RC5.h"
#include "RC6.h"
#include "Camellia.h"
#include "Blowfish.h"
#include "Twofish.h"
#include "CBC.h"
#include "CFB.h"
#include "CTR.h"

NAMESPACE_BEGIN(CryptoMethods)

constexpr uint8_t c_iv[] = { 0x5eu,0x95u,0x7cu,0xe3u,0x2bu,0x79u,0xa1u,0xf9u,0x35u,0x17u,0x8eu,0xdau,0x6cu,0xdeu,0x1du,0x2fu };

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
#if defined(_MSC_VER)
	HCRYPTPROV crypt;
	CryptAcquireContext(&crypt, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(crypt, ivlen, iv);
	CryptReleaseContext(crypt, 0);
#else

#endif
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

inline void CreateAES(CipherBase*& base)
{
	base = new AES;
}

inline void ReleaseAES(CipherBase*& base)
{
	AES* aes = reinterpret_cast<AES*>(base);
	delete aes;
	base = nullptr;
}

inline void CreateRC5(CipherBase*& base)
{
	base = new RC5;
}

inline void ReleaseRC5(CipherBase*& base)
{
	RC5* rc5 = reinterpret_cast<RC5*>(base);
	delete rc5;
	base = nullptr;
}

inline void CreateRC6(CipherBase*& base)
{
	base = new RC6;
}

inline void ReleaseRC6(CipherBase*& base)
{
	RC6* rc6 = reinterpret_cast<RC6*>(base);
	delete rc6;
	base = nullptr;
}

inline void CreateDES(CipherBase*& base)
{
	base = new DES;
}

inline void ReleaseDES(CipherBase*& base)
{
	DES* des = reinterpret_cast<DES*>(base);
	delete des;
	base = nullptr;
}

inline void CreateTripDES(CipherBase*& base)
{
	base = new TripDES;
}

inline void ReleaseTripDES(CipherBase*& base)
{
	TripDES* tripdes = reinterpret_cast<TripDES*>(base);
	delete tripdes;
	base = nullptr;
}

inline void CreateCamellia(CipherBase*& base)
{
	base = new Camellia;
}

inline void ReleaseCamellia(CipherBase*& base)
{
	Camellia* camellia = reinterpret_cast<Camellia*>(base);
	delete camellia;
	base = nullptr;
}

inline void CreateBlowfish(CipherBase*& base)
{
	base = new Blowfish;
}

inline void ReleaseBlowfish(CipherBase*& base)
{
	Blowfish* blowfish = reinterpret_cast<Blowfish*>(base);
	delete blowfish;
	base = nullptr;
}

inline void CreateTwofish(CipherBase*& base)
{
	base = new Twofish;
}

inline void ReleaseTwofish(CipherBase*& base)
{
	Twofish* twofish = reinterpret_cast<Twofish*>(base);
	delete twofish;
	base = nullptr;
}

void CreateCipherBase(enum_crypt_methods method, CipherBase*& base)
{
	switch (method)
	{
	case enum_crypt_methods_des: CreateDES(base); break;
	case enum_crypt_methods_tripdes: CreateTripDES(base); break;
	case enum_crypt_methods_aes: CreateAES(base); break;
	case enum_crypt_methods_rc5: CreateRC5(base); break;
	case enum_crypt_methods_rc6: CreateRC6(base); break;
	case enum_crypt_methods_camellia: CreateCamellia(base); break;
	case enum_crypt_methods_blowfish: CreateBlowfish(base); break;
	case enum_crypt_methods_twofish: CreateTwofish(base); break;
	default: break;
	}
}
void ReleaseCipherBase(enum_crypt_methods method, CipherBase*& base)
{
	switch (method)
	{
	case enum_crypt_methods_des: ReleaseDES(base); break;
	case enum_crypt_methods_tripdes: ReleaseTripDES(base); break;
	case enum_crypt_methods_aes: ReleaseAES(base); break;
	case enum_crypt_methods_rc5: ReleaseRC5(base); break;
	case enum_crypt_methods_rc6: ReleaseRC6(base); break;
	case enum_crypt_methods_camellia: ReleaseCamellia(base); break;
	case enum_crypt_methods_blowfish: ReleaseBlowfish(base); break;
	case enum_crypt_methods_twofish: ReleaseTwofish(base); break;
	default: break;
	}
}

// void AESCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<AES> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 
// 	uint8_t* temp = new uint8_t[inlen + 16];
// 	memcpy(temp, in, sizeof(uint8_t)*inlen);
// 	size_t templen = PKCS7(temp, inlen, 16);
// 
// 	cbc.Encrypt(temp, templen, out, outlen);
// 
// 	delete[] temp;
// }
// 
// void AESCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<AES> cbc;
// 	cbc.SetKey(key, keylen);
// 	uint8_t iv[16]; //= { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
// 	GenerateIV(iv, 16);
// 	cbc.SetIV(iv, 16);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void AESCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<AES> cfb;
// 	cfb.SetKey(key, keylen);
// 	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
// 	//GenerateIV(iv, 16);
// 	cfb.SetIV(iv, 16);
// 
// 	uint8_t* temp = new uint8_t[inlen];
// 	memcpy(temp, in, sizeof(uint8_t)*inlen);
// 	size_t templen = inlen;
// 
// 	cfb.Encrypt(temp, templen, out, outlen);
// 
// 	delete[] temp;
// }
// 
// void AESCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<AES> cfb;
// 	cfb.SetKey(key, keylen);
// 	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
// 	//GenerateIV(iv, 16);
// 	cfb.SetIV(iv, 16);
// 	cfb.Decrypt(in, inlen, out, outlen);
// }
// 
// void AESCTREncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CTR<AES> cbc;
// 	cbc.SetKey(key, keylen);
// 	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
// 	//GenerateIV(iv, 16);
// 	cbc.SetIV(iv, 16);
// 
// 	uint8_t* temp = new uint8_t[inlen];
// 	memcpy(temp, in, sizeof(uint8_t)*inlen);
// 	size_t templen = inlen;
// 
// 	cbc.Encrypt(temp, templen, out, outlen);
// 
// 	delete[] temp;
// }
// 
// void AESCTRDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CTR<AES> cbc;
// 	cbc.SetKey(key, keylen);
// 	uint8_t iv[16] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0','0' };
// 	//GenerateIV(iv, 16);
// 	cbc.SetIV(iv, 16);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void RC5CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<RC5> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 8);
// 	cbc.Encrypt(in, inlen, out, outlen);
// }
// 
// void RC5CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<RC5> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 8);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void RC5CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<RC5> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 8);
// 	cfb.Encrypt(in, inlen, out, outlen);
// }
// 
// void RC5CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<RC5> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 8);
// 	cfb.Decrypt(in, inlen, out, outlen);
// }
// 
// void RC6CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<RC6> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Encrypt(in, inlen, out, outlen);
// }
// 
// void RC6CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<RC6> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void RC6CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<RC6> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Encrypt(in, inlen, out, outlen);
// }
// 
// void RC6CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<RC6> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Decrypt(in, inlen, out, outlen);
// }
// 
// void CamelliaCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<Camellia> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Encrypt(in, inlen, out, outlen);
// }
// 
// void CamelliaCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<Camellia> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void CamelliaCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<Camellia> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Encrypt(in, inlen, out, outlen);
// }
// 
// void CamelliaCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<Camellia> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Decrypt(in, inlen, out, outlen);
// }
// 
// void TwofishCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<Twofish> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Encrypt(in, inlen, out, outlen);
// }
// 
// void TwofishCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CBC<Twofish> cbc;
// 	cbc.SetKey(key, keylen);
// 	cbc.SetIV(c_iv, 16);
// 	cbc.Decrypt(in, inlen, out, outlen);
// }
// 
// void TwofishCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<Twofish> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Encrypt(in, inlen, out, outlen);
// }
// 
// void TwofishCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen)
// {
// 	CFB<Twofish> cfb;
// 	cfb.SetKey(key, keylen);
// 	cfb.SetIV(c_iv, 16);
// 	cfb.Decrypt(in, inlen, out, outlen);
// }

NAMESPACE_END
