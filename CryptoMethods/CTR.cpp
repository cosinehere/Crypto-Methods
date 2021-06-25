#include "pch.h"
#include "CTR.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
CTR<CIPHER>::CTR()
{}

template<class CIPHER>
CTR<CIPHER>::~CTR()
{}

template<class CIPHER>
bool CTR<CIPHER>::Encrypt()
{
	return false;
}

template<class CIPHER>
bool CTR<CIPHER>::Decrypt()
{
	return false;
}

NAMESPACEEND
