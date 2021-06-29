#pragma once

#ifdef _CRYPTOMETHODS_EXPORT_
#define CRYPTOEXT extern "C" __declspec(dllexport)
#else
#define CRYPTOEXT extern "C" _declspec(dllimport)
#endif

#define NOVTABLE __declspec(novtable)

#define NAMESPACEBEGIN(name) namespace name{
#define NAMESPACEEND }

#include <cstdint>

NAMESPACEBEGIN(CryptoMethods)

CRYPTOEXT size_t Padding(uint8_t* buffer, size_t len, size_t blocksize);

CRYPTOEXT void GenerateIV(uint8_t* iv, size_t ivlen);

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

CRYPTOEXT void AESCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void AESCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

CRYPTOEXT void AESCTREncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
CRYPTOEXT void AESCTRDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

NAMESPACEEND