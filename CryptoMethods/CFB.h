#pragma once
#include "CryptoMethodDefines.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
class CFB :	public CipherModeBase
{
public:
	CFB();
	virtual ~CFB();

	virtual bool Encrypt() override;
	virtual bool Decrypt() override;

private:
	CIPHER p_cipher;
};

NAMESPACEEND
