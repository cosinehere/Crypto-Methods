#pragma once
#include "CryptoMethodDefines.h"

NAMESPACE_BEGIN(CryptoMethods)

constexpr size_t c_twofishblocksize = 16;

constexpr uint8_t c_Qtab[2][256]=
{
	{
		0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
		0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
		0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
		0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
		0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
		0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
		0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
		0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
		0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
		0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
		0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
		0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
		0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
		0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
		0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
		0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
	},
	{
		0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
		0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
		0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
		0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
		0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
		0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
		0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
		0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
		0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
		0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
		0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
		0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
		0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
		0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
		0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
		0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
	}
};

/* 2. Standard interface for AES cryptographic routines             */

/* These are all based on 32 bit unsigned values and will therefore */

/* require endian conversions for big-endian architectures          */



/* 3. Basic macros for speeding up generic operations               */

/* Circular rotate of 32 bit values                                 */
#define rotr(x,n) r_rot<uint32_t>(x,n)
#define rotl(x,n) l_rot<uint32_t>(x,n)

// #ifdef _MSC_VER
// #  include <stdlib.h>
// #  pragma intrinsic(_lrotr,_lrotl)
// #  define rotr(x,n) _lrotr(x,n)
// #  define rotl(x,n) _lrotl(x,n)
// #else
// #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
// #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
// #endif

/* Invert byte order in a 32 bit variable                           */
#define bswap(x)    (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)

/* Extract byte from a 32 bit quantity (little endian notation)     */
inline uint8_t byte(uint32_t x, uint32_t n)
{
	return x >> (n << 3);
}

/* For inverting byte order in input/output 32 bit words if needed  */
#ifdef  BLOCK_SWAP
#define BYTE_SWAP
#define WORD_SWAP
#endif

#ifdef  BYTE_SWAP
#define io_swap(x)  bswap(x)
#else
#define io_swap(x)  (x)
#endif

/* For inverting the byte order of input/output blocks if needed    */
#ifdef  WORD_SWAP

#define get_block(x)                            \
((uint32_t*)(x))[0] = io_swap(in_blk[3]);     \
((uint32_t*)(x))[1] = io_swap(in_blk[2]);     \
((uint32_t*)(x))[2] = io_swap(in_blk[1]);     \
((uint32_t*)(x))[3] = io_swap(in_blk[0])

#define put_block(x)                            \
out_blk[3] = io_swap(((uint32_t*)(x))[0]);    \
out_blk[2] = io_swap(((uint32_t*)(x))[1]);    \
out_blk[1] = io_swap(((uint32_t*)(x))[2]);    \
out_blk[0] = io_swap(((uint32_t*)(x))[3])

#define get_key(x,len)                          \
((uint32_t*)(x))[4] = ((uint32_t*)(x))[5] = \
((uint32_t*)(x))[6] = ((uint32_t*)(x))[7] = 0;  \
switch ((((len)+63) / 64)) {	\
case 2:                                     \
		((uint32_t*)(x))[0] = io_swap(in_key[3]);     \
		((uint32_t*)(x))[1] = io_swap(in_key[2]);     \
		((uint32_t*)(x))[2] = io_swap(in_key[1]);     \
		((uint32_t*)(x))[3] = io_swap(in_key[0]);     \
		break;                                      \
case 3:                                     \
		((uint32_t*)(x))[0] = io_swap(in_key[5]);     \
		((uint32_t*)(x))[1] = io_swap(in_key[4]);     \
		((uint32_t*)(x))[2] = io_swap(in_key[3]);     \
		((uint32_t*)(x))[3] = io_swap(in_key[2]);     \
		((uint32_t*)(x))[4] = io_swap(in_key[1]);     \
		((uint32_t*)(x))[5] = io_swap(in_key[0]);     \
		break;                                      \
case 4:                                     \
		((uint32_t*)(x))[0] = io_swap(in_key[7]);     \
		((uint32_t*)(x))[1] = io_swap(in_key[6]);     \
		((uint32_t*)(x))[2] = io_swap(in_key[5]);     \
		((uint32_t*)(x))[3] = io_swap(in_key[4]);     \
		((uint32_t*)(x))[4] = io_swap(in_key[3]);     \
		((uint32_t*)(x))[5] = io_swap(in_key[2]);     \
		((uint32_t*)(x))[6] = io_swap(in_key[1]);     \
		((uint32_t*)(x))[7] = io_swap(in_key[0]);     \
}

#else

#define get_block(x)                            \
((uint32_t*)(x))[0] = io_swap(in_blk[0]);     \
((uint32_t*)(x))[1] = io_swap(in_blk[1]);     \
((uint32_t*)(x))[2] = io_swap(in_blk[2]);     \
((uint32_t*)(x))[3] = io_swap(in_blk[3])

#define put_block(x)                            \
out_blk[0] = io_swap(((uint32_t*)(x))[0]);    \
out_blk[1] = io_swap(((uint32_t*)(x))[1]);    \
out_blk[2] = io_swap(((uint32_t*)(x))[2]);    \
out_blk[3] = io_swap(((uint32_t*)(x))[3])

#define get_key(x,len)                          \
((uint32_t*)(x))[4] = ((uint32_t*)(x))[5] = \
((uint32_t*)(x))[6] = ((uint32_t*)(x))[7] = 0;  \
switch ((((len)+63) / 64)) {	\
case 4:                                     \
		((uint32_t*)(x))[6] = io_swap(in_key[6]);     \
		((uint32_t*)(x))[7] = io_swap(in_key[7]);     \
case 3:                                     \
		((uint32_t*)(x))[4] = io_swap(in_key[4]);     \
		((uint32_t*)(x))[5] = io_swap(in_key[5]);     \
case 2:                                     \
		((uint32_t*)(x))[0] = io_swap(in_key[0]);     \
		((uint32_t*)(x))[1] = io_swap(in_key[1]);     \
		((uint32_t*)(x))[2] = io_swap(in_key[2]);     \
		((uint32_t*)(x))[3] = io_swap(in_key[3]);     \
}

#endif

class Twofish : public CipherBase
{
public:
	Twofish();
	virtual ~Twofish();

	virtual const enum_crypt_methods CryptMethod() { return p_method; }
	virtual const size_t BlockSize() override;

	virtual bool SetKey(const uint8_t* key, const size_t keylen) override;
	virtual bool Encrypt(const uint8_t* plain, uint8_t* cipher) override;
	virtual bool Decrypt(const uint8_t* cipher, uint8_t* plain) override;

private:
	enum_crypt_methods p_method;
	size_t p_blocksize;

	bool p_haskey;

	size_t p_keylen;
	uint8_t p_key[64];

	uint32_t  p_k_len;
	uint32_t  p_l_key[40];
	uint32_t  p_s_key[4];

	uint32_t h_fun(const uint32_t x, const uint32_t key[]);
	void gen_mk_tab(uint32_t key[]);
	uint32_t *set_key(const uint32_t in_key[], const uint32_t key_len);
	void f_rnd(uint32_t i, uint32_t& t0, uint32_t& t1, uint32_t* blk);
	void encrypt(const uint32_t in_blk[4], uint32_t out_blk[4]);
	void i_rnd(uint32_t i, uint32_t& t0, uint32_t& t1, uint32_t* blk);
	void decrypt(const uint32_t in_blk[4], uint32_t out_blk[4]);
};

NAMESPACE_END
