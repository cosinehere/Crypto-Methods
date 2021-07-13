// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <cstdint>
#include <cstdio>
#include <memory.h>

#include "../CryptoMethods/CryptoMethodDefines.h"
#pragma comment(lib,"../CryptoMethods/Debug/CryptoMethods.lib")

void PaddingTest()
{
	uint8_t buffer[16] = { 0 };
	//CryptoMethods::PKCS7(buffer, 8, 8);
	//CryptoMethods::PKCS5(buffer, 8);
	for (size_t i = 0; i < 16; ++i)
	{
		printf("%02x ", buffer[i]);
	}
	printf("\n");
}

void AESCBCtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::AESCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::AESCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void AESCFBtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::AESCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::AESCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void RC5CBCtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::RC5CBCEncrypt(key, 16, plain, 8, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::RC5CBCDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void RC5CFBtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::RC5CFBEncrypt(key, 16, plain, 8, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::RC5CFBDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void RC6CBCtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::RC6CBCEncrypt(key, 16, plain, 16, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::RC6CBCDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void RC6CFBtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::RC6CFBEncrypt(key, 16, plain, 16, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::RC6CFBDecrypt(key, 16, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void CamelliaCBCtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::CamelliaCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::CamelliaCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void CamelliaCFBtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::CamelliaCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::CamelliaCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void TwofishCBCtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::TwofishCBCEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::TwofishCBCDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

void TwofishCFBtest()
{
	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
	size_t cipherlen;

	CryptoMethods::TwofishCFBEncrypt(key, keylen, plain, plainlen, cipher, cipherlen);

	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x ", cipher[i]);
	}
	printf("\n");

	CryptoMethods::TwofishCFBDecrypt(key, keylen, cipher, cipherlen, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%02x ", plain[i]);
	}
	printf("\n");
}

int main()
{
	

	CryptoMethods::CipherBase* base = nullptr;
	// 	CryptoMethods::CreateAES(base);

	uint8_t key[] = "abcdefghijklmnopqrstuvwxyz";
	size_t keylen = 16;
	//	base->SetKey(key, keylen);

	uint8_t plain[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	size_t plainlen = 16;
	uint8_t cipher[33] = { 0 };
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

	uint8_t iv[16] = { '0','0', '0', '0', '1', '1', '1', '1', '2', '2', '2', '2', '3', '3', '3','3' };

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

	TwofishCBCtest();
	TwofishCFBtest();
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧:
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件