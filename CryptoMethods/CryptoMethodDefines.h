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

CRYPTOEXT void Padding(uint8_t* buffer, size_t len, size_t blocksize);

#define PKCS7(buffer,len,blocksize) Padding(buffer,len,blocksize)
#define PKCS5(buffer,len) Padding(buffer,len,8)

enum enum_crypt_mode
{
	enum_crypt_encrypt = 0,
	enum_crypt_decrypt
};

class NOVTABLE CipherBase
{
public:
	virtual bool SetKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) = 0;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) = 0;

	virtual ~CipherBase() {}
};

class NOVTABLE CipherModeBase
{
public:
	virtual bool Encrypt() = 0;
	virtual bool Decrypt() = 0;

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

NAMESPACEEND