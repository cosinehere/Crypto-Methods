#pragma once

#if defined(_MSC_VER)
#ifdef _CRYPTOMETHODS_EXPORT_
#define CRYPTOEXT extern "C" __declspec(dllexport)
#else
#define CRYPTOEXT extern "C" __declspec(dllimport)
#endif

#define NOVTABLE __declspec(novtable)

#else
#define CRYPTOEXT
#define NOVTABLE
#endif

#define NAMESPACE_BEGIN(name) namespace name{
#define NAMESPACE_END }

NAMESPACE_BEGIN(CryptoMethods)

CRYPTOEXT size_t Padding(uint8_t* buffer, size_t len, size_t blocksize);

CRYPTOEXT void GenerateIV(uint8_t* iv, size_t ivlen);

CRYPTOEXT void MixBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix);
CRYPTOEXT void ScatterBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix);

#define PKCS7(buffer,len,blocksize) Padding(buffer,len,blocksize)
#define PKCS5(buffer,len) Padding(buffer,len,8)

constexpr uint8_t c_iv[] = { 0x5eu,0x95u,0x7cu,0xe3u,0x2bu,0x79u,0xa1u,0xf9u,0x35u,0x17u,0x8eu,0xdau,0x6cu,0xdeu,0x1du,0x2fu };

enum enum_crypt_mode
{
	enum_crypt_encrypt = 0,
	enum_crypt_decrypt
};

class NOVTABLE CipherBase
{
public:
	virtual const size_t BlockSize() = 0;
	virtual bool SetKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) = 0;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) = 0;

	virtual ~CipherBase() {}
};

class NOVTABLE CipherModeBase
{
public:
	virtual bool SetKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool SetIV(const uint8_t* iv, const size_t ivlen) = 0;

	virtual bool Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) = 0;
	virtual bool Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) = 0;

	virtual ~CipherModeBase() {}
};

template<typename T>
inline T r_rot(T a, T b)
{
	return (a >> b) | (a << ((sizeof(T) >> 3) - b));
}

template<typename T>
inline T l_rot(T a, T b)
{
	return (a << b) | (a >> ((sizeof(T) >> 3) - b));
}

CRYPTOEXT void CreateAES(CipherBase*& base);
CRYPTOEXT void ReleaseAES(CipherBase*& base);

CRYPTOEXT void CreateRC5(CipherBase*& base);
CRYPTOEXT void ReleaseRC5(CipherBase*& base);

CRYPTOEXT void CreateRC6(CipherBase*& base);
CRYPTOEXT void ReleaseRC6(CipherBase*& base);

CRYPTOEXT void CreateDES(CipherBase*& base);
CRYPTOEXT void ReleaseDES(CipherBase*& base);

CRYPTOEXT void CreateTripDES(CipherBase*& base);
CRYPTOEXT void ReleaseTripDES(CipherBase*& base);

CRYPTOEXT void CreateCamellia(CipherBase*& base);
CRYPTOEXT void ReleaseCamellia(CipherBase*& base);

CRYPTOEXT void CreateBlowfish(CipherBase*& base);
CRYPTOEXT void ReleaseBlowfish(CipherBase*& base);

CRYPTOEXT void CreateTwofish(CipherBase*& base);
CRYPTOEXT void ReleaseTwofish(CipherBase*& base);

CRYPTOEXT void AESCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void AESCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void AESCTREncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCTRDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void RC5CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void RC5CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void RC5CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void RC5CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void RC6CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void RC6CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void RC6CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void RC6CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void CamelliaCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void CamelliaCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void CamelliaCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void CamelliaCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void TwofishCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void TwofishCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void TwofishCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void TwofishCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

NAMESPACE_END
