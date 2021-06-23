#pragma once

#ifdef _CRYPTOMETHODS_EXPORT_
#define CRYPTOEXT extern "C" _declspec(dllexport)
#else
#define CRYPTOEXT extern "C" _declspec(dllimport)
#endif

#include <cstdint>

CRYPTOEXT void PKCS7(uint8_t* buffer, size_t len, size_t blocksize);
