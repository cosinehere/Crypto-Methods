#include "pch.h"
#include "CryptoMethodDefines.h"

#include "AES.h"

NAMESPACEBEGIN(CryptoMethods)

void Padding(uint8_t* buffer, size_t len, size_t blocksize)
{
	size_t left = blocksize - (len % blocksize);
	if (left == 0) left += blocksize;
	for (size_t i = 0; i < left; ++i)
	{
		buffer[len + i] = static_cast<uint8_t>(left);
	}
}

void CreateAES(CipherBase*& base)
{
	base = new AES;
}

void ReleaseAES(CipherBase*& base)
{
	delete base;
	base = nullptr;
}

NAMESPACEEND