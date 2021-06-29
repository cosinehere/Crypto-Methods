// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include "../CryptoMethods/CryptoMethodDefines.h"
#pragma comment(lib,"../CryptoMethods/Debug/CryptoMethods.lib")

int main()
{
    //uint8_t buffer[16] = { 0 };
	//CryptoMethods::PKCS7(buffer, 8, 8);
	//CryptoMethods::PKCS5(buffer, 8);
	//for (size_t i = 0; i < 16; ++i)
	//{
	//	printf("%02x ", buffer[i]);
	//}
	//printf("\n");

	CryptoMethods::CipherBase* base = nullptr;
	CryptoMethods::CreateAES(base);

	uint8_t key[] = "aaaaaaaaaaaaaaaaaaaaaaaa";
	size_t keylen = 24;
	base->SetKey(key, keylen);

	uint8_t plain[32] = "bbbbbbbbbbbbbbbbbbb";
	uint8_t cipher[32] = { 0 };

// 	base->Encrypt(plain, cipher);
// 	for (size_t i = 0; i < 16; ++i)
// 	{
// 		printf("%02x", cipher[i]);
// 	}
// 	printf("\n");
// 
	uint8_t ci[32] = { 18,104,220,29,129,235,155,132,165,207,132,134,190,224,226,62,140,64,130,241,239,94,231,8,228,252,18,209,22,171,69,153 };
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

	size_t cipherlen;
	CryptoMethods::AESCTREncrypt(key, keylen, plain, 19, cipher, cipherlen);
	for (size_t i = 0; i < cipherlen; ++i)
	{
		printf("%02x", cipher[i]);
	}
	printf("\n");

	size_t plainlen;
	CryptoMethods::AESCTRDecrypt(key, keylen, cfb, 16, plain, plainlen);
	for (size_t i = 0; i < plainlen; ++i)
	{
		printf("%c", plain[i]);
	}
	printf("\n");
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
