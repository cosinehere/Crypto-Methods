#pragma once
#include "CryptoMethodDefines.h"

NAMESPACEBEGIN(CryptoMethods)

template<class CIPHER>
class CBC : public CipherModeBase
{
public:
	CBC();
	virtual ~CBC();

	virtual bool Encrypt() override;
	virtual bool Decrypt() override;

private:
	CIPHER p_cipher;
};

NAMESPACEEND
