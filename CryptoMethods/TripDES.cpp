#include "TripDES.h"

#include "pch.h"

NAMESPACE_BEGIN(CryptoMethods)

TripDES::TripDES() {
    p_method = enum_crypt_methods_tripdes;
    p_blocksize = c_desblocksize;

    p_haskey = false;
}

TripDES::~TripDES() {}

const size_t TripDES::BlockSize() { return p_blocksize; }

bool TripDES::SetKey(const uint8_t* key, const size_t keylen) {
    if (key == nullptr || (keylen != c_deskeylen && keylen != c_deskeylen * 2 &&
			   keylen != c_deskeylen * 3)) {
	return false;
    }

    switch (keylen / c_deskeylen) {
	case 1:
	    p_des1.SetKey(key, keylen);
	    p_des2.SetKey(key, keylen);
	    p_des3.SetKey(key, keylen);
	    break;
	case 2:
	    p_des1.SetKey(key, c_deskeylen);
	    p_des2.SetKey(&key[c_deskeylen], c_deskeylen);
	    p_des3.SetKey(key, c_deskeylen);
	    break;
	case 3:
	    p_des1.SetKey(key, c_deskeylen);
	    p_des2.SetKey(&key[c_deskeylen], c_deskeylen);
	    p_des3.SetKey(&key[c_deskeylen * 2], c_deskeylen);
	    break;
	default:
	    return false;
    }

    p_haskey = true;

    return true;
}

bool TripDES::Encrypt(const uint8_t* plain, uint8_t* cipher) {
    if (!p_haskey) {
	return false;
    }

    uint8_t temp1[c_desblocksize];
    uint8_t temp2[c_desblocksize];
    p_des1.Encrypt(plain, temp1);
    p_des2.Decrypt(temp1, temp2);
    p_des3.Encrypt(temp2, cipher);

    return true;
}
bool TripDES::Decrypt(const uint8_t* cipher, uint8_t* plain) {
    if (!p_haskey) {
	return false;
    }

    uint8_t temp1[c_desblocksize];
    uint8_t temp2[c_desblocksize];
    p_des3.Decrypt(cipher, temp1);
    p_des2.Encrypt(temp1, temp2);
    p_des1.Decrypt(temp2, plain);

    return true;
}

NAMESPACE_END
