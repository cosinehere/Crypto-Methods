#include <cstdint>
#include <cstdio>
#include <memory.h>

#include "../CryptoMethods/CryptoMethodDefines.h"
#include "../CryptoMethods/Padding.h"
#pragma comment(lib,"../CryptoMethods/Debug/CryptoMethods")

void PaddingTest()
{
    uint8_t buffer[16] = { 0 };
    size_t len = CryptoMethods::pkcs_5(buffer, 16, 11);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

// void AESCBCtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::AESCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::AESCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void AESCFBtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::AESCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::AESCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void RC5CBCtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::RC5CBCEncrypt(key, 16, plain, 8, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::RC5CBCDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void RC5CFBtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::RC5CFBEncrypt(key, 16, plain, 8, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::RC5CFBDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void RC6CBCtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::RC6CBCEncrypt(key, 16, plain, 16, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::RC6CBCDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void RC6CFBtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::RC6CFBEncrypt(key, 16, plain, 16, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::RC6CFBDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void CamelliaCBCtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::CamelliaCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::CamelliaCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void CamelliaCFBtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::CamelliaCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::CamelliaCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void TwofishCBCtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::TwofishCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::TwofishCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }
// 
// void TwofishCFBtest()
// {
// 	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
// 	size_t keylen = 16;
// 	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
// 	size_t plainlen = 16;
// 	uint8_t cipher[33] = { 0 };
// 	size_t cipherlen;
// 
// 	CryptoMethods::TwofishCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);
// 
// 	for (size_t i = 0; i < cipherlen; ++i)
// 	{
// 		printf("%02x ", cipher[i]);
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::TwofishCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
// 	for (size_t i = 0; i < plainlen; ++i)
// 	{
// 		printf("%02x ", plain[i]);
// 	}
// 	printf("\n");
// }

int main()
{
    //PaddingTest();

    //	CryptoMethods::CipherBase* base = nullptr;
    // 	CryptoMethods::CreateAES(base);

    uint8_t key[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}/*{ 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c }*//*"abcdefghijklmnopqrstuvwxyz"*/;
    size_t keylen = 16;
    //	base->SetKey(key, keylen);

    //uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
//     uint8_t plain[] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
//         0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
//         0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
//         0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
//         0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
//         0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
//         0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
//         0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
    uint8_t plain[] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    size_t plainlen = 16;
    uint8_t cipher[64] = { 0 };
    size_t cipherlen = 0;

    // 	base->Encrypt(plain, cipher);
    // 	for (size_t i = 0; i < 16; ++i)
    // 	{
    // 		printf("%02x", cipher[i]);
    // 	}
    // 	printf("\n");
    //
    uint8_t ci[32] = { 103, 95, 142, 232, 106, 180, 176, 217 };
    uint8_t cfb[32] = { 183,198,10,248,133,1,177,77,96,137,129,222,137,216,206,86 };
    uint8_t ctr[32] = { 183,198,10,248,133,1,177,77,96,137,129,222,137,216,206,86 };
    // 	base->Decrypt(cipher, plain);
    //
    // 	for (size_t i = 0; i < 16; ++i)
    // 	{
    // 		printf("%c", plain[i]);
    // 	}
    // 	printf("\n");
    //
    // 	CryptoMethods::ReleaseAES(base);

    uint8_t iv[16] = /*{ '0','0', '0', '0', '1', '1', '1', '1', '2', '2', '2', '2', '3', '3', '3','3' };*//*{ 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff };*/
    { 0 };
// 	CryptoMethods::CreateTwofish(base);
// 
// 	base->SetKey(key, keylen);
// 	base->Encrypt(plain, cipher);
// 	for (size_t i = 0; i < base->BlockSize(); ++i)
// 	{
// 		printf("%02x%s", plain[i], (i % 8 == 7) ? " " : "");
// 	}
// 	printf("\n");
// 	for (size_t i = 0; i < base->BlockSize(); ++i)
// 	{
// 		printf("%02x%s", cipher[i], (i % 8 == 7) ? " " : "");
// 	}
// 	printf("\n");
// 
// 	memset(plain, 0, sizeof(plain));
// 	base->Decrypt(cipher, plain);
// 	for (size_t i = 0; i < base->BlockSize(); ++i)
// 	{
// 		printf("%02x%s", plain[i], (i % 8 == 7) ? " " : "");
// 	}
// 	printf("\n");
// 
// 	CryptoMethods::ReleaseTwofish(base);

// 	TwofishCBCtest();
// 	TwofishCFBtest();

    for (size_t i = 0; i < plainlen; ++i)
    {
        printf("%02x%s", plain[i], (i % 8 == 7) ? " " : "");
    }
    printf("\n");

    CryptoMethods::CipherBase* base = nullptr;
    CryptoMethods::CreateCipherBase(CryptoMethods::enum_crypt_methods_sm4, base);
    CryptoMethods::CipherModeBase* modebase = nullptr;
    CryptoMethods::CreateCipherMode(CryptoMethods::enum_crypt_mode_cbc, base, modebase);
    modebase->SetKey(key, keylen);
    modebase->SetIV(iv, base->BlockSize());
    modebase->Encrypt(plain, plainlen, cipher, cipherlen);
    for (size_t i = 0; i < cipherlen; ++i)
    {
        printf("%02x%s", cipher[i], (i % 8 == 7) ? " " : "");
    }
    printf("\n");

    modebase->SetIV(iv, base->BlockSize());
    modebase->Decrypt(cipher, cipherlen, plain, plainlen);
    for (size_t i = 0; i < plainlen; ++i)
    {
        printf("%02x%s", plain[i], (i % 8 == 7) ? " " : "");
    }
    printf("\n");

    CryptoMethods::ReleaseCipherMode(modebase);
    CryptoMethods::ReleaseCipherBase(base);
}
