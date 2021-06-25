#pragma once
#include "CryptoMethodDefines.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
class CTR :	public CipherModeBase
{
public:
	CTR();
	virtual ~CTR();

	virtual bool Encrypt() override;
	virtual bool Decrypt() override;

private:
	CIPHER p_cipher;
};


NAMESPACEEND
