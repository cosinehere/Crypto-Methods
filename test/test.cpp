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

	uint8_t key[] = "aaaaaaaaaaaaaaaa";
	base->SetKey(key, 16);

	uint8_t plain[] = "bbbbbbbbbbbbbbbb";
	uint8_t cipher[16] = { 0 };

	base->Encrypt(plain, cipher);
	for (size_t i = 0; i < 16; ++i)
	{
		printf("%02x", cipher[i]);
	}
	printf("\n");

	uint8_t ci[16] = { 183, 25,16,11,34,30,173,155,60,97,115,214,249,24,66,230 };
	base->Decrypt(ci, plain);

	for (size_t i = 0; i < 16; ++i)
	{
		printf("%c", plain[i]);
	}
	printf("\n");

	CryptoMethods::ReleaseAES(base);
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
