#pragma once

namespace CryptoMethods {

inline size_t pkcs_7(uint8_t *buffer, size_t buflen, size_t datalen, uint8_t blocksize) {
    uint8_t left = blocksize - (datalen % blocksize);
    if (left == 0) { left = blocksize; }
    if (buflen < datalen + left) { return 0; }

    for (size_t i = 0; i < left; ++i) {
        buffer[datalen + i] = left;
    }

    return datalen + left;
}

#define pkcs_5(buffer, buflen, datalen) pkcs_7(buffer, buflen, datalen, 8)

}
