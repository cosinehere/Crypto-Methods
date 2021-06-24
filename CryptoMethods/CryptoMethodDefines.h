#pragma once

#ifdef _CRYPTOMETHODS_EXPORT_
#define CRYPTOEXT extern "C" _declspec(dllexport)
#else
#define CRYPTOEXT extern "C" _declspec(dllimport)
#endif

#include <cstdint>

CRYPTOEXT void PKCS7(uint8_t* buffer, size_t len, size_t blocksize);

enum enum_crypt_mode
{
	enum_crypt_encrypt = 0,
	enum_crypt_decrypt
};

class __declspec(novtable) CipherBase
{
public:
	virtual bool SetMode(enum_crypt_mode mode) = 0;
	virtual bool UpdateKey(const uint8_t* key, const size_t keylen) = 0;
	virtual bool UpdateIV(const uint8_t* iv, const size_t ivlen) = 0;
	virtual bool UpdateData(const uint8_t* data, const size_t datalen) = 0;
	virtual bool Finally(uint8_t* out, size_t* outlen) = 0;

	virtual ~CipherBase() {}
};

class __declspec(novtable) CipherModeBase
{
public:
	virtual bool Encrypt() = 0;
	virtual bool Decrypt() = 0;

	virtual ~CipherModeBase() {}
};

template<class CIPHER>
class CBC_Mode : public CipherModeBase
{
public:
	CBC_Mode() = default;
	virtual ~CBC_Mode() = default;

	virtual bool Encrypt() override { return false; };
	virtual bool Decrypt() override { return false; };

private:
	CIPHER p_cipher;
};

template<class CIPHER>
class CFB_Mode
{
public:
	CFB_Mode() = default;
	virtual ~CFB_Mode() = default;

	void Encrypt() {};
	void Decrypt() {};

private:
	CIPHER p_cipher;
};

template<class CIPHER>
class CTR_Mode
{
public:
	CTR_Mode() = default;
	virtual ~CTR_Mode() = default;

	void Encrypt() {};
	void Decrypt() {};

private:
	CIPHER p_cipher;
};

class AES : public CipherBase
{
public:
	AES() = default;
	virtual ~AES() = default;

	virtual bool SetMode(enum_crypt_mode mode) override { return false; };
	virtual bool UpdateKey(const uint8_t* key, const size_t keylen) { return false; };
	virtual bool UpdateIV(const uint8_t* iv, const size_t ivlen) { return false; };
	virtual bool UpdateData(const uint8_t* data, const size_t datalen) { return false; };
	virtual bool Finally(uint8_t* out, size_t* outlen) { return false; };
};
