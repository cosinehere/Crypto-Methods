#pragma once

#if defined(_MSC_VER)
#ifdef _CRYPTOMETHODSLIB_EXPORT_
#define CRYPTOEXT
#elif defined(_CRYPTOMETHODSDLL_EXPORT_)
#define CRYPTOEXT extern "C" __declspec(dllexport)
#else
#define CRYPTOEXT extern "C" __declspec(dllimport)
#endif

#define NOVTABLE __declspec(novtable)

#else
#ifdef _CRYPTOMETHODSDLL_EXPORT_
#define CRYPTOEXT extern "C" __attribute__((visibility("default")))
#else
#define CRYPTOEXT
#endif

#define NOVTABLE
#endif

#if !defined(NAMESPACE_BEGIN) && !defined(NAMESPACE_END)
#define NAMESPACE_BEGIN(name) namespace name{
#define NAMESPACE_END }
#endif	// !defined(NAMESPACE_BEGIN) && !defined(NAMESPACE_END)

NAMESPACE_BEGIN(CryptoMethods)

CRYPTOEXT size_t Padding(uint8_t* buffer, size_t len, size_t blocksize);

CRYPTOEXT void GenerateIV(uint8_t* iv, size_t ivlen);

CRYPTOEXT void MixBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix);
CRYPTOEXT void ScatterBytes(uint8_t* key, uint8_t* iv, uint8_t* cipher, size_t cipherlen, uint8_t* mix);

#define PKCS7(buffer,len,blocksize) Padding(buffer,len,blocksize)
#define PKCS5(buffer,len) Padding(buffer,len,8)

enum enum_crypt_methods
{
	enum_crypt_methods_des = 0,
	enum_crypt_methods_tripdes,
	enum_crypt_methods_aes,
	enum_crypt_methods_rc5,
	enum_crypt_methods_rc6,
	enum_crypt_methods_camellia,
	enum_crypt_methods_blowfish,
	enum_crypt_methods_twofish,

	enum_crypt_methods_end,
	enum_crypt_methods_num = enum_crypt_methods_end - enum_crypt_methods_des
};

enum enum_crypt_modes
{
	enum_crypt_mode_cbc = 0,
	enum_crypt_mode_cfb,
	enum_crypt_mode_ctr,

	enum_crypt_mode_end,
	enum_crypt_mode_num = enum_crypt_mode_end - enum_crypt_mode_cbc,
};

class NOVTABLE CipherBase
{
public:
	virtual const enum_crypt_methods CryptMethod() = 0;
	virtual const size_t BlockSize() = 0;

	virtual bool SetKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) = 0;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) = 0;

	virtual ~CipherBase() {}
};

class NOVTABLE CipherModeBase
{
public:
	virtual const enum_crypt_modes CryptMode() = 0;

	virtual bool SetKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool SetIV(const uint8_t* iv, const size_t ivlen) = 0;

	virtual bool Encrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) = 0;
	virtual bool Decrypt(const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen) = 0;

	virtual ~CipherModeBase() {}
};

CRYPTOEXT void CreateCipherBase(enum_crypt_methods method, CipherBase*& base);
CRYPTOEXT void ReleaseCipherBase(CipherBase*& base);

CRYPTOEXT void CreateCipherMode(enum_crypt_modes mode, CipherBase* cipher, CipherModeBase*& base);
CRYPTOEXT void ReleaseCipherMode(CipherModeBase*& base);

// CRYPTOEXT void AESCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void AESCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void AESCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void AESCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void AESCTREncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void AESCTRDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void RC5CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void RC5CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void RC5CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void RC5CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void RC6CBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void RC6CBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void RC6CFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void RC6CFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void CamelliaCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void CamelliaCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void CamelliaCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void CamelliaCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void TwofishCBCEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void TwofishCBCDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// 
// CRYPTOEXT void TwofishCFBEncrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);
// CRYPTOEXT void TwofishCFBDecrypt(const uint8_t* key, const size_t keylen, const uint8_t* in, const size_t inlen, uint8_t* out, size_t& outlen);

NAMESPACE_END
