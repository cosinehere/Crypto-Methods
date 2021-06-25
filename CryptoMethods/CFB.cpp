#include "pch.h"
#include "CFB.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
CFB<CIPHER>::CFB()
{}

template<class CIPHER>
CFB<CIPHER>::~CFB()
{}

template<class CIPHER>
bool CFB<CIPHER>::Encrypt()
{
	return false;
}

template<class CIPHER>
bool CFB<CIPHER>::Decrypt()
{
	return false;
}

NAMESPACEEND
