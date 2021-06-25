#include "pch.h"
#include "CBC.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
CBC<CIPHER>::CBC()
{
	;
}

template<class CIPHER>
CBC<CIPHER>::~CBC()
{
	;
}

template<class CIPHER>
bool CBC<CIPHER>::Encrypt()
{
	return false;
}

template<class CIPHER>
bool CBC<CIPHER>::Decrypt()
{
	return false;
}

NAMESPACEEND
