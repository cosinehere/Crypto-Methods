#include "pch.h"

#include "Camellia.h"

#include <cstdlib>

namespace CryptoMethods {

/* key constants */

#define CAMELLIA_SIGMA1L (0xA09E667FL)
#define CAMELLIA_SIGMA1R (0x3BCC908BL)
#define CAMELLIA_SIGMA2L (0xB67AE858L)
#define CAMELLIA_SIGMA2R (0x4CAA73B2L)
#define CAMELLIA_SIGMA3L (0xC6EF372FL)
#define CAMELLIA_SIGMA3R (0xE94F82BEL)
#define CAMELLIA_SIGMA4L (0x54FF53A5L)
#define CAMELLIA_SIGMA4R (0xF1D36F1CL)
#define CAMELLIA_SIGMA5L (0x10E527FAL)
#define CAMELLIA_SIGMA5R (0xDE682D1DL)
#define CAMELLIA_SIGMA6L (0xB05688C2L)
#define CAMELLIA_SIGMA6R (0xB3E6C1FDL)

/*
 *  macros
 */

#if defined(_MSC_VER)

#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define GETU32(p) SWAP(*((uint32_t *)(p)))
#define PUTU32(ct, st) \
    { *((uint32_t *)(ct)) = SWAP((st)); }

#else /* not MS-VC */

#define GETU32(pt)                                           \
    (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ \
     ((uint32_t)(pt)[2] << 8) ^ ((uint32_t)(pt)[3]))

#define PUTU32(ct, st)                   \
    {                                    \
        (ct)[0] = (uint8_t)((st) >> 24); \
        (ct)[1] = (uint8_t)((st) >> 16); \
        (ct)[2] = (uint8_t)((st) >> 8);  \
        (ct)[3] = (uint8_t)(st);         \
    }

#endif

#define CamelliaSubkeyL(INDEX) (subkey[(INDEX)*2])
#define CamelliaSubkeyR(INDEX) (subkey[(INDEX)*2 + 1])

/* rotation right shift 1byte */
#define CAMELLIA_RR8(x) (((x) >> 8) + ((x) << 24))
/* rotation left shift 1bit */
#define CAMELLIA_RL1(x) (((x) << 1) + ((x) >> 31))
/* rotation left shift 1byte */
#define CAMELLIA_RL8(x) (((x) << 8) + ((x) >> 24))

#define CAMELLIA_ROLDQ(ll, lr, rl, rr, w0, w1, bits) \
    do {                                             \
        w0 = ll;                                     \
        ll = (ll << bits) + (lr >> (32 - bits));     \
        lr = (lr << bits) + (rl >> (32 - bits));     \
        rl = (rl << bits) + (rr >> (32 - bits));     \
        rr = (rr << bits) + (w0 >> (32 - bits));     \
    } while (0)

#define CAMELLIA_ROLDQo32(ll, lr, rl, rr, w0, w1, bits) \
    do {                                                \
        w0 = ll;                                        \
        w1 = lr;                                        \
        ll = (lr << (bits - 32)) + (rl >> (64 - bits)); \
        lr = (rl << (bits - 32)) + (rr >> (64 - bits)); \
        rl = (rr << (bits - 32)) + (w0 >> (64 - bits)); \
        rr = (w0 << (bits - 32)) + (w1 >> (64 - bits)); \
    } while (0)

#define CAMELLIA_SP1110(INDEX) (camellia_sp1110[(INDEX)])
#define CAMELLIA_SP0222(INDEX) (camellia_sp0222[(INDEX)])
#define CAMELLIA_SP3033(INDEX) (camellia_sp3033[(INDEX)])
#define CAMELLIA_SP4404(INDEX) (camellia_sp4404[(INDEX)])

#define CAMELLIA_F(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)                    \
    do {                                                                      \
        il = xl ^ kl;                                                         \
        ir = xr ^ kr;                                                         \
        t0 = il >> 16;                                                        \
        t1 = ir >> 16;                                                        \
        yl = CAMELLIA_SP1110(ir & 0xff) ^ CAMELLIA_SP0222((t1 >> 8) & 0xff) ^ \
             CAMELLIA_SP3033(t1 & 0xff) ^ CAMELLIA_SP4404((ir >> 8) & 0xff);  \
        yr = CAMELLIA_SP1110((t0 >> 8) & 0xff) ^ CAMELLIA_SP0222(t0 & 0xff) ^ \
             CAMELLIA_SP3033((il >> 8) & 0xff) ^ CAMELLIA_SP4404(il & 0xff);  \
        yl ^= yr;                                                             \
        yr = CAMELLIA_RR8(yr);                                                \
        yr ^= yl;                                                             \
    } while (0)

/*
 * for speed up
 *
 */
#define CAMELLIA_FLS(ll, lr, rl, rr, kll, klr, krl, krr, t0, t1, t2, t3) \
    do {                                                                 \
        t0 = kll;                                                        \
        t0 &= ll;                                                        \
        lr ^= CAMELLIA_RL1(t0);                                          \
        t1 = klr;                                                        \
        t1 |= lr;                                                        \
        ll ^= t1;                                                        \
                                                                         \
        t2 = krr;                                                        \
        t2 |= rr;                                                        \
        rl ^= t2;                                                        \
        t3 = krl;                                                        \
        t3 &= rl;                                                        \
        rr ^= CAMELLIA_RL1(t3);                                          \
    } while (0)

#define CAMELLIA_ROUNDSM(xl, xr, kl, kr, yl, yr, il, ir, t0, t1)               \
    do {                                                                       \
        ir = CAMELLIA_SP1110(xr & 0xff) ^ CAMELLIA_SP0222((xr >> 24) & 0xff) ^ \
             CAMELLIA_SP3033((xr >> 16) & 0xff) ^                              \
             CAMELLIA_SP4404((xr >> 8) & 0xff);                                \
        il = CAMELLIA_SP1110((xl >> 24) & 0xff) ^                              \
             CAMELLIA_SP0222((xl >> 16) & 0xff) ^                              \
             CAMELLIA_SP3033((xl >> 8) & 0xff) ^ CAMELLIA_SP4404(xl & 0xff);   \
        il ^= kl;                                                              \
        ir ^= kr;                                                              \
        ir ^= il;                                                              \
        il = CAMELLIA_RR8(il);                                                 \
        il ^= ir;                                                              \
        yl ^= ir;                                                              \
        yr ^= il;                                                              \
    } while (0)

static const uint32_t camellia_sp1110[256] = {
    0x70707000u, 0x82828200u, 0x2c2c2c00u, 0xececec00u, 0xb3b3b300u, 0x27272700u,
    0xc0c0c000u, 0xe5e5e500u, 0xe4e4e400u, 0x85858500u, 0x57575700u, 0x35353500u,
    0xeaeaea00u, 0x0c0c0c00u, 0xaeaeae00u, 0x41414100u, 0x23232300u, 0xefefef00u,
    0x6b6b6b00u, 0x93939300u, 0x45454500u, 0x19191900u, 0xa5a5a500u, 0x21212100u,
    0xededed00u, 0x0e0e0e00u, 0x4f4f4f00u, 0x4e4e4e00u, 0x1d1d1d00u, 0x65656500u,
    0x92929200u, 0xbdbdbd00u, 0x86868600u, 0xb8b8b800u, 0xafafaf00u, 0x8f8f8f00u,
    0x7c7c7c00u, 0xebebeb00u, 0x1f1f1f00u, 0xcecece00u, 0x3e3e3e00u, 0x30303000u,
    0xdcdcdc00u, 0x5f5f5f00u, 0x5e5e5e00u, 0xc5c5c500u, 0x0b0b0b00u, 0x1a1a1a00u,
    0xa6a6a600u, 0xe1e1e100u, 0x39393900u, 0xcacaca00u, 0xd5d5d500u, 0x47474700u,
    0x5d5d5d00u, 0x3d3d3d00u, 0xd9d9d900u, 0x01010100u, 0x5a5a5a00u, 0xd6d6d600u,
    0x51515100u, 0x56565600u, 0x6c6c6c00u, 0x4d4d4d00u, 0x8b8b8b00u, 0x0d0d0d00u,
    0x9a9a9a00u, 0x66666600u, 0xfbfbfb00u, 0xcccccc00u, 0xb0b0b000u, 0x2d2d2d00u,
    0x74747400u, 0x12121200u, 0x2b2b2b00u, 0x20202000u, 0xf0f0f000u, 0xb1b1b100u,
    0x84848400u, 0x99999900u, 0xdfdfdf00u, 0x4c4c4c00u, 0xcbcbcb00u, 0xc2c2c200u,
    0x34343400u, 0x7e7e7e00u, 0x76767600u, 0x05050500u, 0x6d6d6d00u, 0xb7b7b700u,
    0xa9a9a900u, 0x31313100u, 0xd1d1d100u, 0x17171700u, 0x04040400u, 0xd7d7d700u,
    0x14141400u, 0x58585800u, 0x3a3a3a00u, 0x61616100u, 0xdedede00u, 0x1b1b1b00u,
    0x11111100u, 0x1c1c1c00u, 0x32323200u, 0x0f0f0f00u, 0x9c9c9c00u, 0x16161600u,
    0x53535300u, 0x18181800u, 0xf2f2f200u, 0x22222200u, 0xfefefe00u, 0x44444400u,
    0xcfcfcf00u, 0xb2b2b200u, 0xc3c3c300u, 0xb5b5b500u, 0x7a7a7a00u, 0x91919100u,
    0x24242400u, 0x08080800u, 0xe8e8e800u, 0xa8a8a800u, 0x60606000u, 0xfcfcfc00u,
    0x69696900u, 0x50505000u, 0xaaaaaa00u, 0xd0d0d000u, 0xa0a0a000u, 0x7d7d7d00u,
    0xa1a1a100u, 0x89898900u, 0x62626200u, 0x97979700u, 0x54545400u, 0x5b5b5b00u,
    0x1e1e1e00u, 0x95959500u, 0xe0e0e000u, 0xffffff00u, 0x64646400u, 0xd2d2d200u,
    0x10101000u, 0xc4c4c400u, 0x00000000u, 0x48484800u, 0xa3a3a300u, 0xf7f7f700u,
    0x75757500u, 0xdbdbdb00u, 0x8a8a8a00u, 0x03030300u, 0xe6e6e600u, 0xdadada00u,
    0x09090900u, 0x3f3f3f00u, 0xdddddd00u, 0x94949400u, 0x87878700u, 0x5c5c5c00u,
    0x83838300u, 0x02020200u, 0xcdcdcd00u, 0x4a4a4a00u, 0x90909000u, 0x33333300u,
    0x73737300u, 0x67676700u, 0xf6f6f600u, 0xf3f3f300u, 0x9d9d9d00u, 0x7f7f7f00u,
    0xbfbfbf00u, 0xe2e2e200u, 0x52525200u, 0x9b9b9b00u, 0xd8d8d800u, 0x26262600u,
    0xc8c8c800u, 0x37373700u, 0xc6c6c600u, 0x3b3b3b00u, 0x81818100u, 0x96969600u,
    0x6f6f6f00u, 0x4b4b4b00u, 0x13131300u, 0xbebebe00u, 0x63636300u, 0x2e2e2e00u,
    0xe9e9e900u, 0x79797900u, 0xa7a7a700u, 0x8c8c8c00u, 0x9f9f9f00u, 0x6e6e6e00u,
    0xbcbcbc00u, 0x8e8e8e00u, 0x29292900u, 0xf5f5f500u, 0xf9f9f900u, 0xb6b6b600u,
    0x2f2f2f00u, 0xfdfdfd00u, 0xb4b4b400u, 0x59595900u, 0x78787800u, 0x98989800u,
    0x06060600u, 0x6a6a6a00u, 0xe7e7e700u, 0x46464600u, 0x71717100u, 0xbababa00u,
    0xd4d4d400u, 0x25252500u, 0xababab00u, 0x42424200u, 0x88888800u, 0xa2a2a200u,
    0x8d8d8d00u, 0xfafafa00u, 0x72727200u, 0x07070700u, 0xb9b9b900u, 0x55555500u,
    0xf8f8f800u, 0xeeeeee00u, 0xacacac00u, 0x0a0a0a00u, 0x36363600u, 0x49494900u,
    0x2a2a2a00u, 0x68686800u, 0x3c3c3c00u, 0x38383800u, 0xf1f1f100u, 0xa4a4a400u,
    0x40404000u, 0x28282800u, 0xd3d3d300u, 0x7b7b7b00u, 0xbbbbbb00u, 0xc9c9c900u,
    0x43434300u, 0xc1c1c100u, 0x15151500u, 0xe3e3e300u, 0xadadad00u, 0xf4f4f400u,
    0x77777700u, 0xc7c7c700u, 0x80808000u, 0x9e9e9e00u,
};

static const uint32_t camellia_sp0222[256] = {
    0x00e0e0e0u, 0x00050505u, 0x00585858u, 0x00d9d9d9u, 0x00676767u, 0x004e4e4eu,
    0x00818181u, 0x00cbcbcbu, 0x00c9c9c9u, 0x000b0b0bu, 0x00aeaeaeu, 0x006a6a6au,
    0x00d5d5d5u, 0x00181818u, 0x005d5d5du, 0x00828282u, 0x00464646u, 0x00dfdfdfu,
    0x00d6d6d6u, 0x00272727u, 0x008a8a8au, 0x00323232u, 0x004b4b4bu, 0x00424242u,
    0x00dbdbdbu, 0x001c1c1cu, 0x009e9e9eu, 0x009c9c9cu, 0x003a3a3au, 0x00cacacau,
    0x00252525u, 0x007b7b7bu, 0x000d0d0du, 0x00717171u, 0x005f5f5fu, 0x001f1f1fu,
    0x00f8f8f8u, 0x00d7d7d7u, 0x003e3e3eu, 0x009d9d9du, 0x007c7c7cu, 0x00606060u,
    0x00b9b9b9u, 0x00bebebeu, 0x00bcbcbcu, 0x008b8b8bu, 0x00161616u, 0x00343434u,
    0x004d4d4du, 0x00c3c3c3u, 0x00727272u, 0x00959595u, 0x00abababu, 0x008e8e8eu,
    0x00bababau, 0x007a7a7au, 0x00b3b3b3u, 0x00020202u, 0x00b4b4b4u, 0x00adadadu,
    0x00a2a2a2u, 0x00acacacu, 0x00d8d8d8u, 0x009a9a9au, 0x00171717u, 0x001a1a1au,
    0x00353535u, 0x00ccccccu, 0x00f7f7f7u, 0x00999999u, 0x00616161u, 0x005a5a5au,
    0x00e8e8e8u, 0x00242424u, 0x00565656u, 0x00404040u, 0x00e1e1e1u, 0x00636363u,
    0x00090909u, 0x00333333u, 0x00bfbfbfu, 0x00989898u, 0x00979797u, 0x00858585u,
    0x00686868u, 0x00fcfcfcu, 0x00ecececu, 0x000a0a0au, 0x00dadadau, 0x006f6f6fu,
    0x00535353u, 0x00626262u, 0x00a3a3a3u, 0x002e2e2eu, 0x00080808u, 0x00afafafu,
    0x00282828u, 0x00b0b0b0u, 0x00747474u, 0x00c2c2c2u, 0x00bdbdbdu, 0x00363636u,
    0x00222222u, 0x00383838u, 0x00646464u, 0x001e1e1eu, 0x00393939u, 0x002c2c2cu,
    0x00a6a6a6u, 0x00303030u, 0x00e5e5e5u, 0x00444444u, 0x00fdfdfdu, 0x00888888u,
    0x009f9f9fu, 0x00656565u, 0x00878787u, 0x006b6b6bu, 0x00f4f4f4u, 0x00232323u,
    0x00484848u, 0x00101010u, 0x00d1d1d1u, 0x00515151u, 0x00c0c0c0u, 0x00f9f9f9u,
    0x00d2d2d2u, 0x00a0a0a0u, 0x00555555u, 0x00a1a1a1u, 0x00414141u, 0x00fafafau,
    0x00434343u, 0x00131313u, 0x00c4c4c4u, 0x002f2f2fu, 0x00a8a8a8u, 0x00b6b6b6u,
    0x003c3c3cu, 0x002b2b2bu, 0x00c1c1c1u, 0x00ffffffu, 0x00c8c8c8u, 0x00a5a5a5u,
    0x00202020u, 0x00898989u, 0x00000000u, 0x00909090u, 0x00474747u, 0x00efefefu,
    0x00eaeaeau, 0x00b7b7b7u, 0x00151515u, 0x00060606u, 0x00cdcdcdu, 0x00b5b5b5u,
    0x00121212u, 0x007e7e7eu, 0x00bbbbbbu, 0x00292929u, 0x000f0f0fu, 0x00b8b8b8u,
    0x00070707u, 0x00040404u, 0x009b9b9bu, 0x00949494u, 0x00212121u, 0x00666666u,
    0x00e6e6e6u, 0x00cececeu, 0x00edededu, 0x00e7e7e7u, 0x003b3b3bu, 0x00fefefeu,
    0x007f7f7fu, 0x00c5c5c5u, 0x00a4a4a4u, 0x00373737u, 0x00b1b1b1u, 0x004c4c4cu,
    0x00919191u, 0x006e6e6eu, 0x008d8d8du, 0x00767676u, 0x00030303u, 0x002d2d2du,
    0x00dededeu, 0x00969696u, 0x00262626u, 0x007d7d7du, 0x00c6c6c6u, 0x005c5c5cu,
    0x00d3d3d3u, 0x00f2f2f2u, 0x004f4f4fu, 0x00191919u, 0x003f3f3fu, 0x00dcdcdcu,
    0x00797979u, 0x001d1d1du, 0x00525252u, 0x00ebebebu, 0x00f3f3f3u, 0x006d6d6du,
    0x005e5e5eu, 0x00fbfbfbu, 0x00696969u, 0x00b2b2b2u, 0x00f0f0f0u, 0x00313131u,
    0x000c0c0cu, 0x00d4d4d4u, 0x00cfcfcfu, 0x008c8c8cu, 0x00e2e2e2u, 0x00757575u,
    0x00a9a9a9u, 0x004a4a4au, 0x00575757u, 0x00848484u, 0x00111111u, 0x00454545u,
    0x001b1b1bu, 0x00f5f5f5u, 0x00e4e4e4u, 0x000e0e0eu, 0x00737373u, 0x00aaaaaau,
    0x00f1f1f1u, 0x00ddddddu, 0x00595959u, 0x00141414u, 0x006c6c6cu, 0x00929292u,
    0x00545454u, 0x00d0d0d0u, 0x00787878u, 0x00707070u, 0x00e3e3e3u, 0x00494949u,
    0x00808080u, 0x00505050u, 0x00a7a7a7u, 0x00f6f6f6u, 0x00777777u, 0x00939393u,
    0x00868686u, 0x00838383u, 0x002a2a2au, 0x00c7c7c7u, 0x005b5b5bu, 0x00e9e9e9u,
    0x00eeeeeeu, 0x008f8f8fu, 0x00010101u, 0x003d3d3du,
};

static const uint32_t camellia_sp3033[256] = {
    0x38003838u, 0x41004141u, 0x16001616u, 0x76007676u, 0xd900d9d9u, 0x93009393u,
    0x60006060u, 0xf200f2f2u, 0x72007272u, 0xc200c2c2u, 0xab00ababu, 0x9a009a9au,
    0x75007575u, 0x06000606u, 0x57005757u, 0xa000a0a0u, 0x91009191u, 0xf700f7f7u,
    0xb500b5b5u, 0xc900c9c9u, 0xa200a2a2u, 0x8c008c8cu, 0xd200d2d2u, 0x90009090u,
    0xf600f6f6u, 0x07000707u, 0xa700a7a7u, 0x27002727u, 0x8e008e8eu, 0xb200b2b2u,
    0x49004949u, 0xde00dedeu, 0x43004343u, 0x5c005c5cu, 0xd700d7d7u, 0xc700c7c7u,
    0x3e003e3eu, 0xf500f5f5u, 0x8f008f8fu, 0x67006767u, 0x1f001f1fu, 0x18001818u,
    0x6e006e6eu, 0xaf00afafu, 0x2f002f2fu, 0xe200e2e2u, 0x85008585u, 0x0d000d0du,
    0x53005353u, 0xf000f0f0u, 0x9c009c9cu, 0x65006565u, 0xea00eaeau, 0xa300a3a3u,
    0xae00aeaeu, 0x9e009e9eu, 0xec00ececu, 0x80008080u, 0x2d002d2du, 0x6b006b6bu,
    0xa800a8a8u, 0x2b002b2bu, 0x36003636u, 0xa600a6a6u, 0xc500c5c5u, 0x86008686u,
    0x4d004d4du, 0x33003333u, 0xfd00fdfdu, 0x66006666u, 0x58005858u, 0x96009696u,
    0x3a003a3au, 0x09000909u, 0x95009595u, 0x10001010u, 0x78007878u, 0xd800d8d8u,
    0x42004242u, 0xcc00ccccu, 0xef00efefu, 0x26002626u, 0xe500e5e5u, 0x61006161u,
    0x1a001a1au, 0x3f003f3fu, 0x3b003b3bu, 0x82008282u, 0xb600b6b6u, 0xdb00dbdbu,
    0xd400d4d4u, 0x98009898u, 0xe800e8e8u, 0x8b008b8bu, 0x02000202u, 0xeb00ebebu,
    0x0a000a0au, 0x2c002c2cu, 0x1d001d1du, 0xb000b0b0u, 0x6f006f6fu, 0x8d008d8du,
    0x88008888u, 0x0e000e0eu, 0x19001919u, 0x87008787u, 0x4e004e4eu, 0x0b000b0bu,
    0xa900a9a9u, 0x0c000c0cu, 0x79007979u, 0x11001111u, 0x7f007f7fu, 0x22002222u,
    0xe700e7e7u, 0x59005959u, 0xe100e1e1u, 0xda00dadau, 0x3d003d3du, 0xc800c8c8u,
    0x12001212u, 0x04000404u, 0x74007474u, 0x54005454u, 0x30003030u, 0x7e007e7eu,
    0xb400b4b4u, 0x28002828u, 0x55005555u, 0x68006868u, 0x50005050u, 0xbe00bebeu,
    0xd000d0d0u, 0xc400c4c4u, 0x31003131u, 0xcb00cbcbu, 0x2a002a2au, 0xad00adadu,
    0x0f000f0fu, 0xca00cacau, 0x70007070u, 0xff00ffffu, 0x32003232u, 0x69006969u,
    0x08000808u, 0x62006262u, 0x00000000u, 0x24002424u, 0xd100d1d1u, 0xfb00fbfbu,
    0xba00babau, 0xed00ededu, 0x45004545u, 0x81008181u, 0x73007373u, 0x6d006d6du,
    0x84008484u, 0x9f009f9fu, 0xee00eeeeu, 0x4a004a4au, 0xc300c3c3u, 0x2e002e2eu,
    0xc100c1c1u, 0x01000101u, 0xe600e6e6u, 0x25002525u, 0x48004848u, 0x99009999u,
    0xb900b9b9u, 0xb300b3b3u, 0x7b007b7bu, 0xf900f9f9u, 0xce00ceceu, 0xbf00bfbfu,
    0xdf00dfdfu, 0x71007171u, 0x29002929u, 0xcd00cdcdu, 0x6c006c6cu, 0x13001313u,
    0x64006464u, 0x9b009b9bu, 0x63006363u, 0x9d009d9du, 0xc000c0c0u, 0x4b004b4bu,
    0xb700b7b7u, 0xa500a5a5u, 0x89008989u, 0x5f005f5fu, 0xb100b1b1u, 0x17001717u,
    0xf400f4f4u, 0xbc00bcbcu, 0xd300d3d3u, 0x46004646u, 0xcf00cfcfu, 0x37003737u,
    0x5e005e5eu, 0x47004747u, 0x94009494u, 0xfa00fafau, 0xfc00fcfcu, 0x5b005b5bu,
    0x97009797u, 0xfe00fefeu, 0x5a005a5au, 0xac00acacu, 0x3c003c3cu, 0x4c004c4cu,
    0x03000303u, 0x35003535u, 0xf300f3f3u, 0x23002323u, 0xb800b8b8u, 0x5d005d5du,
    0x6a006a6au, 0x92009292u, 0xd500d5d5u, 0x21002121u, 0x44004444u, 0x51005151u,
    0xc600c6c6u, 0x7d007d7du, 0x39003939u, 0x83008383u, 0xdc00dcdcu, 0xaa00aaaau,
    0x7c007c7cu, 0x77007777u, 0x56005656u, 0x05000505u, 0x1b001b1bu, 0xa400a4a4u,
    0x15001515u, 0x34003434u, 0x1e001e1eu, 0x1c001c1cu, 0xf800f8f8u, 0x52005252u,
    0x20002020u, 0x14001414u, 0xe900e9e9u, 0xbd00bdbdu, 0xdd00ddddu, 0xe400e4e4u,
    0xa100a1a1u, 0xe000e0e0u, 0x8a008a8au, 0xf100f1f1u, 0xd600d6d6u, 0x7a007a7au,
    0xbb00bbbbu, 0xe300e3e3u, 0x40004040u, 0x4f004f4fu,
};

static const uint32_t camellia_sp4404[256] = {
    0x70700070u, 0x2c2c002cu, 0xb3b300b3u, 0xc0c000c0u, 0xe4e400e4u, 0x57570057u,
    0xeaea00eau, 0xaeae00aeu, 0x23230023u, 0x6b6b006bu, 0x45450045u, 0xa5a500a5u,
    0xeded00edu, 0x4f4f004fu, 0x1d1d001du, 0x92920092u, 0x86860086u, 0xafaf00afu,
    0x7c7c007cu, 0x1f1f001fu, 0x3e3e003eu, 0xdcdc00dcu, 0x5e5e005eu, 0x0b0b000bu,
    0xa6a600a6u, 0x39390039u, 0xd5d500d5u, 0x5d5d005du, 0xd9d900d9u, 0x5a5a005au,
    0x51510051u, 0x6c6c006cu, 0x8b8b008bu, 0x9a9a009au, 0xfbfb00fbu, 0xb0b000b0u,
    0x74740074u, 0x2b2b002bu, 0xf0f000f0u, 0x84840084u, 0xdfdf00dfu, 0xcbcb00cbu,
    0x34340034u, 0x76760076u, 0x6d6d006du, 0xa9a900a9u, 0xd1d100d1u, 0x04040004u,
    0x14140014u, 0x3a3a003au, 0xdede00deu, 0x11110011u, 0x32320032u, 0x9c9c009cu,
    0x53530053u, 0xf2f200f2u, 0xfefe00feu, 0xcfcf00cfu, 0xc3c300c3u, 0x7a7a007au,
    0x24240024u, 0xe8e800e8u, 0x60600060u, 0x69690069u, 0xaaaa00aau, 0xa0a000a0u,
    0xa1a100a1u, 0x62620062u, 0x54540054u, 0x1e1e001eu, 0xe0e000e0u, 0x64640064u,
    0x10100010u, 0x00000000u, 0xa3a300a3u, 0x75750075u, 0x8a8a008au, 0xe6e600e6u,
    0x09090009u, 0xdddd00ddu, 0x87870087u, 0x83830083u, 0xcdcd00cdu, 0x90900090u,
    0x73730073u, 0xf6f600f6u, 0x9d9d009du, 0xbfbf00bfu, 0x52520052u, 0xd8d800d8u,
    0xc8c800c8u, 0xc6c600c6u, 0x81810081u, 0x6f6f006fu, 0x13130013u, 0x63630063u,
    0xe9e900e9u, 0xa7a700a7u, 0x9f9f009fu, 0xbcbc00bcu, 0x29290029u, 0xf9f900f9u,
    0x2f2f002fu, 0xb4b400b4u, 0x78780078u, 0x06060006u, 0xe7e700e7u, 0x71710071u,
    0xd4d400d4u, 0xabab00abu, 0x88880088u, 0x8d8d008du, 0x72720072u, 0xb9b900b9u,
    0xf8f800f8u, 0xacac00acu, 0x36360036u, 0x2a2a002au, 0x3c3c003cu, 0xf1f100f1u,
    0x40400040u, 0xd3d300d3u, 0xbbbb00bbu, 0x43430043u, 0x15150015u, 0xadad00adu,
    0x77770077u, 0x80800080u, 0x82820082u, 0xecec00ecu, 0x27270027u, 0xe5e500e5u,
    0x85850085u, 0x35350035u, 0x0c0c000cu, 0x41410041u, 0xefef00efu, 0x93930093u,
    0x19190019u, 0x21210021u, 0x0e0e000eu, 0x4e4e004eu, 0x65650065u, 0xbdbd00bdu,
    0xb8b800b8u, 0x8f8f008fu, 0xebeb00ebu, 0xcece00ceu, 0x30300030u, 0x5f5f005fu,
    0xc5c500c5u, 0x1a1a001au, 0xe1e100e1u, 0xcaca00cau, 0x47470047u, 0x3d3d003du,
    0x01010001u, 0xd6d600d6u, 0x56560056u, 0x4d4d004du, 0x0d0d000du, 0x66660066u,
    0xcccc00ccu, 0x2d2d002du, 0x12120012u, 0x20200020u, 0xb1b100b1u, 0x99990099u,
    0x4c4c004cu, 0xc2c200c2u, 0x7e7e007eu, 0x05050005u, 0xb7b700b7u, 0x31310031u,
    0x17170017u, 0xd7d700d7u, 0x58580058u, 0x61610061u, 0x1b1b001bu, 0x1c1c001cu,
    0x0f0f000fu, 0x16160016u, 0x18180018u, 0x22220022u, 0x44440044u, 0xb2b200b2u,
    0xb5b500b5u, 0x91910091u, 0x08080008u, 0xa8a800a8u, 0xfcfc00fcu, 0x50500050u,
    0xd0d000d0u, 0x7d7d007du, 0x89890089u, 0x97970097u, 0x5b5b005bu, 0x95950095u,
    0xffff00ffu, 0xd2d200d2u, 0xc4c400c4u, 0x48480048u, 0xf7f700f7u, 0xdbdb00dbu,
    0x03030003u, 0xdada00dau, 0x3f3f003fu, 0x94940094u, 0x5c5c005cu, 0x02020002u,
    0x4a4a004au, 0x33330033u, 0x67670067u, 0xf3f300f3u, 0x7f7f007fu, 0xe2e200e2u,
    0x9b9b009bu, 0x26260026u, 0x37370037u, 0x3b3b003bu, 0x96960096u, 0x4b4b004bu,
    0xbebe00beu, 0x2e2e002eu, 0x79790079u, 0x8c8c008cu, 0x6e6e006eu, 0x8e8e008eu,
    0xf5f500f5u, 0xb6b600b6u, 0xfdfd00fdu, 0x59590059u, 0x98980098u, 0x6a6a006au,
    0x46460046u, 0xbaba00bau, 0x25250025u, 0x42420042u, 0xa2a200a2u, 0xfafa00fau,
    0x07070007u, 0x55550055u, 0xeeee00eeu, 0x0a0a000au, 0x49490049u, 0x68680068u,
    0x38380038u, 0xa4a400a4u, 0x28280028u, 0x7b7b007bu, 0xc9c900c9u, 0xc1c100c1u,
    0xe3e300e3u, 0xf4f400f4u, 0xc7c700c7u, 0x9e9e009eu,
};

/**
 * Stuff related to the Camellia key schedule
 */
#define subl(x) subL[(x)]
#define subr(x) subR[(x)]

void camellia_setup128(const uint8_t *key, uint32_t *subkey) {
    uint32_t kll, klr, krl, krr;
    uint32_t il, ir, t0, t1, w0, w1;
    uint32_t kw4l, kw4r, dw, tl, tr;
    uint32_t subL[26];
    uint32_t subR[26];

    /**
     *  k == kll || klr || krl || krr (|| is concatination)
     */
    kll = GETU32(key);
    klr = GETU32(key + 4);
    krl = GETU32(key + 8);
    krr = GETU32(key + 12);
    /**
     * generate KL dependent subkeys
     */
    subl(0) = kll;
    subr(0) = klr;
    subl(1) = krl;
    subr(1) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(4) = kll;
    subr(4) = klr;
    subl(5) = krl;
    subr(5) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(10) = kll;
    subr(10) = klr;
    subl(11) = krl;
    subr(11) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(13) = krl;
    subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(16) = kll;
    subr(16) = klr;
    subl(17) = krl;
    subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(18) = kll;
    subr(18) = klr;
    subl(19) = krl;
    subr(19) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll;
    subr(22) = klr;
    subl(23) = krl;
    subr(23) = krr;

    /* generate KA */
    kll = subl(0);
    klr = subr(0);
    krl = subl(1);
    krr = subr(1);
    CAMELLIA_F(kll, klr, CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R, w0, w1, il, ir, t0,
               t1);
    krl ^= w0;
    krr ^= w1;
    CAMELLIA_F(krl, krr, CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R, kll, klr, il, ir,
               t0, t1);
    CAMELLIA_F(kll, klr, CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R, krl, krr, il, ir,
               t0, t1);
    krl ^= w0;
    krr ^= w1;
    CAMELLIA_F(krl, krr, CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R, w0, w1, il, ir, t0,
               t1);
    kll ^= w0;
    klr ^= w1;

    /* generate KA dependent subkeys */
    subl(2) = kll;
    subr(2) = klr;
    subl(3) = krl;
    subr(3) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll;
    subr(6) = klr;
    subl(7) = krl;
    subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(8) = kll;
    subr(8) = klr;
    subl(9) = krl;
    subr(9) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(12) = kll;
    subr(12) = klr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(14) = kll;
    subr(14) = klr;
    subl(15) = krl;
    subr(15) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(20) = kll;
    subr(20) = klr;
    subl(21) = krl;
    subr(21) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(24) = kll;
    subr(24) = klr;
    subl(25) = krl;
    subr(25) = krr;

    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1);
    subr(3) ^= subr(1);
    subl(5) ^= subl(1);
    subr(5) ^= subr(1);
    subl(7) ^= subl(1);
    subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1);
    subr(11) ^= subr(1);
    subl(13) ^= subl(1);
    subr(13) ^= subr(1);
    subl(15) ^= subl(1);
    subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1);
    subr(19) ^= subr(1);
    subl(21) ^= subl(1);
    subr(21) ^= subr(1);
    subl(23) ^= subl(1);
    subr(23) ^= subr(1);
    subl(24) ^= subl(1);
    subr(24) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(25);
    kw4r = subr(25);
    subl(22) ^= kw4l;
    subr(22) ^= kw4r;
    subl(20) ^= kw4l;
    subr(20) ^= kw4r;
    subl(18) ^= kw4l;
    subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l;
    subr(14) ^= kw4r;
    subl(12) ^= kw4l;
    subr(12) ^= kw4r;
    subl(10) ^= kw4l;
    subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l;
    subr(6) ^= kw4r;
    subl(4) ^= kw4l;
    subr(4) ^= kw4r;
    subl(2) ^= kw4l;
    subr(2) ^= kw4r;
    subl(0) ^= kw4l;
    subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    CamelliaSubkeyL(23) = subl(22);
    CamelliaSubkeyR(23) = subr(22);
    CamelliaSubkeyL(24) = subl(24) ^ subl(23);
    CamelliaSubkeyR(24) = subr(24) ^ subr(23);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;

    return;
}

void camellia_setup256(const unsigned char *key, uint32_t *subkey) {
    uint32_t kll, klr, krl, krr;     /* left half of key */
    uint32_t krll, krlr, krrl, krrr; /* right half of key */
    uint32_t il, ir, t0, t1, w0, w1; /* temporary variables */
    uint32_t kw4l, kw4r, dw, tl, tr;
    uint32_t subL[34];
    uint32_t subR[34];

    /**
     *  key = (kll || klr || krl || krr || krll || krlr || krrl || krrr)
     *  (|| is concatination)
     */

    kll = GETU32(key);
    klr = GETU32(key + 4);
    krl = GETU32(key + 8);
    krr = GETU32(key + 12);
    krll = GETU32(key + 16);
    krlr = GETU32(key + 20);
    krrl = GETU32(key + 24);
    krrr = GETU32(key + 28);

    /* generate KL dependent subkeys */
    subl(0) = kll;
    subr(0) = klr;
    subl(1) = krl;
    subr(1) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 45);
    subl(12) = kll;
    subr(12) = klr;
    subl(13) = krl;
    subr(13) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(16) = kll;
    subr(16) = klr;
    subl(17) = krl;
    subr(17) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 17);
    subl(22) = kll;
    subr(22) = klr;
    subl(23) = krl;
    subr(23) = krr;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 34);
    subl(30) = kll;
    subr(30) = klr;
    subl(31) = krl;
    subr(31) = krr;

    /* generate KR dependent subkeys */
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(4) = krll;
    subr(4) = krlr;
    subl(5) = krrl;
    subr(5) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 15);
    subl(8) = krll;
    subr(8) = krlr;
    subl(9) = krrl;
    subr(9) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(18) = krll;
    subr(18) = krlr;
    subl(19) = krrl;
    subr(19) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);
    subl(26) = krll;
    subr(26) = krlr;
    subl(27) = krrl;
    subr(27) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 34);

    /* generate KA */
    kll = subl(0) ^ krll;
    klr = subr(0) ^ krlr;
    krl = subl(1) ^ krrl;
    krr = subr(1) ^ krrr;
    CAMELLIA_F(kll, klr, CAMELLIA_SIGMA1L, CAMELLIA_SIGMA1R, w0, w1, il, ir, t0,
               t1);
    krl ^= w0;
    krr ^= w1;
    CAMELLIA_F(krl, krr, CAMELLIA_SIGMA2L, CAMELLIA_SIGMA2R, kll, klr, il, ir,
               t0, t1);
    kll ^= krll;
    klr ^= krlr;
    CAMELLIA_F(kll, klr, CAMELLIA_SIGMA3L, CAMELLIA_SIGMA3R, krl, krr, il, ir,
               t0, t1);
    krl ^= w0 ^ krrl;
    krr ^= w1 ^ krrr;
    CAMELLIA_F(krl, krr, CAMELLIA_SIGMA4L, CAMELLIA_SIGMA4R, w0, w1, il, ir, t0,
               t1);
    kll ^= w0;
    klr ^= w1;

    /* generate KB */
    krll ^= kll;
    krlr ^= klr;
    krrl ^= krl;
    krrr ^= krr;
    CAMELLIA_F(krll, krlr, CAMELLIA_SIGMA5L, CAMELLIA_SIGMA5R, w0, w1, il, ir,
               t0, t1);
    krrl ^= w0;
    krrr ^= w1;
    CAMELLIA_F(krrl, krrr, CAMELLIA_SIGMA6L, CAMELLIA_SIGMA6R, w0, w1, il, ir,
               t0, t1);
    krll ^= w0;
    krlr ^= w1;

    /* generate KA dependent subkeys */
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 15);
    subl(6) = kll;
    subr(6) = klr;
    subl(7) = krl;
    subr(7) = krr;
    CAMELLIA_ROLDQ(kll, klr, krl, krr, w0, w1, 30);
    subl(14) = kll;
    subr(14) = klr;
    subl(15) = krl;
    subr(15) = krr;
    subl(24) = klr;
    subr(24) = krl;
    subl(25) = krr;
    subr(25) = kll;
    CAMELLIA_ROLDQo32(kll, klr, krl, krr, w0, w1, 49);
    subl(28) = kll;
    subr(28) = klr;
    subl(29) = krl;
    subr(29) = krr;

    /* generate KB dependent subkeys */
    subl(2) = krll;
    subr(2) = krlr;
    subl(3) = krrl;
    subr(3) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(10) = krll;
    subr(10) = krlr;
    subl(11) = krrl;
    subr(11) = krrr;
    CAMELLIA_ROLDQ(krll, krlr, krrl, krrr, w0, w1, 30);
    subl(20) = krll;
    subr(20) = krlr;
    subl(21) = krrl;
    subr(21) = krrr;
    CAMELLIA_ROLDQo32(krll, krlr, krrl, krrr, w0, w1, 51);
    subl(32) = krll;
    subr(32) = krlr;
    subl(33) = krrl;
    subr(33) = krrr;

    /* absorb kw2 to other subkeys */
    subl(3) ^= subl(1);
    subr(3) ^= subr(1);
    subl(5) ^= subl(1);
    subr(5) ^= subr(1);
    subl(7) ^= subl(1);
    subr(7) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(9);
    dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw);
    subl(11) ^= subl(1);
    subr(11) ^= subr(1);
    subl(13) ^= subl(1);
    subr(13) ^= subr(1);
    subl(15) ^= subl(1);
    subr(15) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(17);
    dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw);
    subl(19) ^= subl(1);
    subr(19) ^= subr(1);
    subl(21) ^= subl(1);
    subr(21) ^= subr(1);
    subl(23) ^= subl(1);
    subr(23) ^= subr(1);
    subl(1) ^= subr(1) & ~subr(25);
    dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw);
    subl(27) ^= subl(1);
    subr(27) ^= subr(1);
    subl(29) ^= subl(1);
    subr(29) ^= subr(1);
    subl(31) ^= subl(1);
    subr(31) ^= subr(1);
    subl(32) ^= subl(1);
    subr(32) ^= subr(1);

    /* absorb kw4 to other subkeys */
    kw4l = subl(33);
    kw4r = subr(33);
    subl(30) ^= kw4l;
    subr(30) ^= kw4r;
    subl(28) ^= kw4l;
    subr(28) ^= kw4r;
    subl(26) ^= kw4l;
    subr(26) ^= kw4r;
    kw4l ^= kw4r & ~subr(24);
    dw = kw4l & subl(24), kw4r ^= CAMELLIA_RL1(dw);
    subl(22) ^= kw4l;
    subr(22) ^= kw4r;
    subl(20) ^= kw4l;
    subr(20) ^= kw4r;
    subl(18) ^= kw4l;
    subr(18) ^= kw4r;
    kw4l ^= kw4r & ~subr(16);
    dw = kw4l & subl(16), kw4r ^= CAMELLIA_RL1(dw);
    subl(14) ^= kw4l;
    subr(14) ^= kw4r;
    subl(12) ^= kw4l;
    subr(12) ^= kw4r;
    subl(10) ^= kw4l;
    subr(10) ^= kw4r;
    kw4l ^= kw4r & ~subr(8);
    dw = kw4l & subl(8), kw4r ^= CAMELLIA_RL1(dw);
    subl(6) ^= kw4l;
    subr(6) ^= kw4r;
    subl(4) ^= kw4l;
    subr(4) ^= kw4r;
    subl(2) ^= kw4l;
    subr(2) ^= kw4r;
    subl(0) ^= kw4l;
    subr(0) ^= kw4r;

    /* key XOR is end of F-function */
    CamelliaSubkeyL(0) = subl(0) ^ subl(2);
    CamelliaSubkeyR(0) = subr(0) ^ subr(2);
    CamelliaSubkeyL(2) = subl(3);
    CamelliaSubkeyR(2) = subr(3);
    CamelliaSubkeyL(3) = subl(2) ^ subl(4);
    CamelliaSubkeyR(3) = subr(2) ^ subr(4);
    CamelliaSubkeyL(4) = subl(3) ^ subl(5);
    CamelliaSubkeyR(4) = subr(3) ^ subr(5);
    CamelliaSubkeyL(5) = subl(4) ^ subl(6);
    CamelliaSubkeyR(5) = subr(4) ^ subr(6);
    CamelliaSubkeyL(6) = subl(5) ^ subl(7);
    CamelliaSubkeyR(6) = subr(5) ^ subr(7);
    tl = subl(10) ^ (subr(10) & ~subr(8));
    dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(7) = subl(6) ^ tl;
    CamelliaSubkeyR(7) = subr(6) ^ tr;
    CamelliaSubkeyL(8) = subl(8);
    CamelliaSubkeyR(8) = subr(8);
    CamelliaSubkeyL(9) = subl(9);
    CamelliaSubkeyR(9) = subr(9);
    tl = subl(7) ^ (subr(7) & ~subr(9));
    dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(10) = tl ^ subl(11);
    CamelliaSubkeyR(10) = tr ^ subr(11);
    CamelliaSubkeyL(11) = subl(10) ^ subl(12);
    CamelliaSubkeyR(11) = subr(10) ^ subr(12);
    CamelliaSubkeyL(12) = subl(11) ^ subl(13);
    CamelliaSubkeyR(12) = subr(11) ^ subr(13);
    CamelliaSubkeyL(13) = subl(12) ^ subl(14);
    CamelliaSubkeyR(13) = subr(12) ^ subr(14);
    CamelliaSubkeyL(14) = subl(13) ^ subl(15);
    CamelliaSubkeyR(14) = subr(13) ^ subr(15);
    tl = subl(18) ^ (subr(18) & ~subr(16));
    dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(15) = subl(14) ^ tl;
    CamelliaSubkeyR(15) = subr(14) ^ tr;
    CamelliaSubkeyL(16) = subl(16);
    CamelliaSubkeyR(16) = subr(16);
    CamelliaSubkeyL(17) = subl(17);
    CamelliaSubkeyR(17) = subr(17);
    tl = subl(15) ^ (subr(15) & ~subr(17));
    dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(18) = tl ^ subl(19);
    CamelliaSubkeyR(18) = tr ^ subr(19);
    CamelliaSubkeyL(19) = subl(18) ^ subl(20);
    CamelliaSubkeyR(19) = subr(18) ^ subr(20);
    CamelliaSubkeyL(20) = subl(19) ^ subl(21);
    CamelliaSubkeyR(20) = subr(19) ^ subr(21);
    CamelliaSubkeyL(21) = subl(20) ^ subl(22);
    CamelliaSubkeyR(21) = subr(20) ^ subr(22);
    CamelliaSubkeyL(22) = subl(21) ^ subl(23);
    CamelliaSubkeyR(22) = subr(21) ^ subr(23);
    tl = subl(26) ^ (subr(26) & ~subr(24));
    dw = tl & subl(24), tr = subr(26) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(23) = subl(22) ^ tl;
    CamelliaSubkeyR(23) = subr(22) ^ tr;
    CamelliaSubkeyL(24) = subl(24);
    CamelliaSubkeyR(24) = subr(24);
    CamelliaSubkeyL(25) = subl(25);
    CamelliaSubkeyR(25) = subr(25);
    tl = subl(23) ^ (subr(23) & ~subr(25));
    dw = tl & subl(25), tr = subr(23) ^ CAMELLIA_RL1(dw);
    CamelliaSubkeyL(26) = tl ^ subl(27);
    CamelliaSubkeyR(26) = tr ^ subr(27);
    CamelliaSubkeyL(27) = subl(26) ^ subl(28);
    CamelliaSubkeyR(27) = subr(26) ^ subr(28);
    CamelliaSubkeyL(28) = subl(27) ^ subl(29);
    CamelliaSubkeyR(28) = subr(27) ^ subr(29);
    CamelliaSubkeyL(29) = subl(28) ^ subl(30);
    CamelliaSubkeyR(29) = subr(28) ^ subr(30);
    CamelliaSubkeyL(30) = subl(29) ^ subl(31);
    CamelliaSubkeyR(30) = subr(29) ^ subr(31);
    CamelliaSubkeyL(31) = subl(30);
    CamelliaSubkeyR(31) = subr(30);
    CamelliaSubkeyL(32) = subl(32) ^ subl(31);
    CamelliaSubkeyR(32) = subr(32) ^ subr(31);

    /* apply the inverse of the last half of P-function */
    dw = CamelliaSubkeyL(2) ^ CamelliaSubkeyR(2), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(2) = CamelliaSubkeyL(2) ^ dw, CamelliaSubkeyL(2) = dw;
    dw = CamelliaSubkeyL(3) ^ CamelliaSubkeyR(3), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(3) = CamelliaSubkeyL(3) ^ dw, CamelliaSubkeyL(3) = dw;
    dw = CamelliaSubkeyL(4) ^ CamelliaSubkeyR(4), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(4) = CamelliaSubkeyL(4) ^ dw, CamelliaSubkeyL(4) = dw;
    dw = CamelliaSubkeyL(5) ^ CamelliaSubkeyR(5), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(5) = CamelliaSubkeyL(5) ^ dw, CamelliaSubkeyL(5) = dw;
    dw = CamelliaSubkeyL(6) ^ CamelliaSubkeyR(6), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(6) = CamelliaSubkeyL(6) ^ dw, CamelliaSubkeyL(6) = dw;
    dw = CamelliaSubkeyL(7) ^ CamelliaSubkeyR(7), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(7) = CamelliaSubkeyL(7) ^ dw, CamelliaSubkeyL(7) = dw;
    dw = CamelliaSubkeyL(10) ^ CamelliaSubkeyR(10), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(10) = CamelliaSubkeyL(10) ^ dw, CamelliaSubkeyL(10) = dw;
    dw = CamelliaSubkeyL(11) ^ CamelliaSubkeyR(11), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(11) = CamelliaSubkeyL(11) ^ dw, CamelliaSubkeyL(11) = dw;
    dw = CamelliaSubkeyL(12) ^ CamelliaSubkeyR(12), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(12) = CamelliaSubkeyL(12) ^ dw, CamelliaSubkeyL(12) = dw;
    dw = CamelliaSubkeyL(13) ^ CamelliaSubkeyR(13), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(13) = CamelliaSubkeyL(13) ^ dw, CamelliaSubkeyL(13) = dw;
    dw = CamelliaSubkeyL(14) ^ CamelliaSubkeyR(14), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(14) = CamelliaSubkeyL(14) ^ dw, CamelliaSubkeyL(14) = dw;
    dw = CamelliaSubkeyL(15) ^ CamelliaSubkeyR(15), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(15) = CamelliaSubkeyL(15) ^ dw, CamelliaSubkeyL(15) = dw;
    dw = CamelliaSubkeyL(18) ^ CamelliaSubkeyR(18), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(18) = CamelliaSubkeyL(18) ^ dw, CamelliaSubkeyL(18) = dw;
    dw = CamelliaSubkeyL(19) ^ CamelliaSubkeyR(19), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(19) = CamelliaSubkeyL(19) ^ dw, CamelliaSubkeyL(19) = dw;
    dw = CamelliaSubkeyL(20) ^ CamelliaSubkeyR(20), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(20) = CamelliaSubkeyL(20) ^ dw, CamelliaSubkeyL(20) = dw;
    dw = CamelliaSubkeyL(21) ^ CamelliaSubkeyR(21), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(21) = CamelliaSubkeyL(21) ^ dw, CamelliaSubkeyL(21) = dw;
    dw = CamelliaSubkeyL(22) ^ CamelliaSubkeyR(22), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(22) = CamelliaSubkeyL(22) ^ dw, CamelliaSubkeyL(22) = dw;
    dw = CamelliaSubkeyL(23) ^ CamelliaSubkeyR(23), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(23) = CamelliaSubkeyL(23) ^ dw, CamelliaSubkeyL(23) = dw;
    dw = CamelliaSubkeyL(26) ^ CamelliaSubkeyR(26), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(26) = CamelliaSubkeyL(26) ^ dw, CamelliaSubkeyL(26) = dw;
    dw = CamelliaSubkeyL(27) ^ CamelliaSubkeyR(27), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(27) = CamelliaSubkeyL(27) ^ dw, CamelliaSubkeyL(27) = dw;
    dw = CamelliaSubkeyL(28) ^ CamelliaSubkeyR(28), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(28) = CamelliaSubkeyL(28) ^ dw, CamelliaSubkeyL(28) = dw;
    dw = CamelliaSubkeyL(29) ^ CamelliaSubkeyR(29), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(29) = CamelliaSubkeyL(29) ^ dw, CamelliaSubkeyL(29) = dw;
    dw = CamelliaSubkeyL(30) ^ CamelliaSubkeyR(30), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(30) = CamelliaSubkeyL(30) ^ dw, CamelliaSubkeyL(30) = dw;
    dw = CamelliaSubkeyL(31) ^ CamelliaSubkeyR(31), dw = CAMELLIA_RL8(dw);
    CamelliaSubkeyR(31) = CamelliaSubkeyL(31) ^ dw, CamelliaSubkeyL(31) = dw;

    return;
}

void camellia_setup192(const uint8_t *key, uint32_t *subkey) {
    uint8_t kk[32];
    uint32_t krll, krlr, krrl, krrr;

    memcpy(kk, key, 24);
    memcpy(&krll, key + 16, 4);
    memcpy(&krlr, key + 20, 4);
    krrl = ~krll;
    krrr = ~krlr;
    memcpy(kk + 24, &krrl, 4);
    memcpy(kk + 28, &krrr, 4);
    camellia_setup256(kk, subkey);
    return;
}

/**
 * Stuff related to camellia encryption/decryption
 *
 * "io" must be 4byte aligned and big-endian data.
 */
void camellia_encrypt128(const uint32_t *subkey, uint32_t *io) {
    uint32_t il, ir, t0, t1;

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);
    /* main iteration */

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(2), CamelliaSubkeyR(2),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(3), CamelliaSubkeyR(3),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(4), CamelliaSubkeyR(4),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(5), CamelliaSubkeyR(5),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(6), CamelliaSubkeyR(6),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(7), CamelliaSubkeyR(7),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(8),
                 CamelliaSubkeyR(8), CamelliaSubkeyL(9), CamelliaSubkeyR(9), t0,
                 t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(10), CamelliaSubkeyR(10),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(11), CamelliaSubkeyR(11),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(12), CamelliaSubkeyR(12),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(13), CamelliaSubkeyR(13),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(14), CamelliaSubkeyR(14),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(15), CamelliaSubkeyR(15),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(16),
                 CamelliaSubkeyR(16), CamelliaSubkeyL(17), CamelliaSubkeyR(17),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(18), CamelliaSubkeyR(18),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(19), CamelliaSubkeyR(19),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(20), CamelliaSubkeyR(20),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(21), CamelliaSubkeyR(21),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(22), CamelliaSubkeyR(22),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(23), CamelliaSubkeyR(23),
                     io[0], io[1], il, ir, t0, t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(24);
    io[3] ^= CamelliaSubkeyR(24);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

void camellia_decrypt128(const uint32_t *subkey, uint32_t *io) {
    uint32_t il, ir, t0, t1; /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(24);
    io[1] ^= CamelliaSubkeyR(24);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(23), CamelliaSubkeyR(23),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(22), CamelliaSubkeyR(22),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(21), CamelliaSubkeyR(21),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(20), CamelliaSubkeyR(20),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(19), CamelliaSubkeyR(19),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(18), CamelliaSubkeyR(18),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(17),
                 CamelliaSubkeyR(17), CamelliaSubkeyL(16), CamelliaSubkeyR(16),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(15), CamelliaSubkeyR(15),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(14), CamelliaSubkeyR(14),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(13), CamelliaSubkeyR(13),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(12), CamelliaSubkeyR(12),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(11), CamelliaSubkeyR(11),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(10), CamelliaSubkeyR(10),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(9),
                 CamelliaSubkeyR(9), CamelliaSubkeyL(8), CamelliaSubkeyR(8), t0,
                 t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(7), CamelliaSubkeyR(7),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(6), CamelliaSubkeyR(6),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(5), CamelliaSubkeyR(5),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(4), CamelliaSubkeyR(4),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(3), CamelliaSubkeyR(3),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(2), CamelliaSubkeyR(2),
                     io[0], io[1], il, ir, t0, t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/**
 * stuff for 192 and 256bit encryption/decryption
 */
void camellia_encrypt256(const uint32_t *subkey, uint32_t *io) {
    uint32_t il, ir, t0, t1; /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(0);
    io[1] ^= CamelliaSubkeyR(0);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(2), CamelliaSubkeyR(2),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(3), CamelliaSubkeyR(3),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(4), CamelliaSubkeyR(4),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(5), CamelliaSubkeyR(5),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(6), CamelliaSubkeyR(6),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(7), CamelliaSubkeyR(7),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(8),
                 CamelliaSubkeyR(8), CamelliaSubkeyL(9), CamelliaSubkeyR(9), t0,
                 t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(10), CamelliaSubkeyR(10),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(11), CamelliaSubkeyR(11),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(12), CamelliaSubkeyR(12),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(13), CamelliaSubkeyR(13),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(14), CamelliaSubkeyR(14),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(15), CamelliaSubkeyR(15),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(16),
                 CamelliaSubkeyR(16), CamelliaSubkeyL(17), CamelliaSubkeyR(17),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(18), CamelliaSubkeyR(18),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(19), CamelliaSubkeyR(19),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(20), CamelliaSubkeyR(20),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(21), CamelliaSubkeyR(21),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(22), CamelliaSubkeyR(22),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(23), CamelliaSubkeyR(23),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(24),
                 CamelliaSubkeyR(24), CamelliaSubkeyL(25), CamelliaSubkeyR(25),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(26), CamelliaSubkeyR(26),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(27), CamelliaSubkeyR(27),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(28), CamelliaSubkeyR(28),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(29), CamelliaSubkeyR(29),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(30), CamelliaSubkeyR(30),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(31), CamelliaSubkeyR(31),
                     io[0], io[1], il, ir, t0, t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(32);
    io[3] ^= CamelliaSubkeyR(32);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

void camellia_decrypt256(const uint32_t *subkey, uint32_t *io) {
    uint32_t il, ir, t0, t1; /* temporary valiables */

    /* pre whitening but absorb kw2*/
    io[0] ^= CamelliaSubkeyL(32);
    io[1] ^= CamelliaSubkeyR(32);

    /* main iteration */
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(31), CamelliaSubkeyR(31),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(30), CamelliaSubkeyR(30),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(29), CamelliaSubkeyR(29),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(28), CamelliaSubkeyR(28),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(27), CamelliaSubkeyR(27),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(26), CamelliaSubkeyR(26),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(25),
                 CamelliaSubkeyR(25), CamelliaSubkeyL(24), CamelliaSubkeyR(24),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(23), CamelliaSubkeyR(23),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(22), CamelliaSubkeyR(22),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(21), CamelliaSubkeyR(21),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(20), CamelliaSubkeyR(20),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(19), CamelliaSubkeyR(19),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(18), CamelliaSubkeyR(18),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(17),
                 CamelliaSubkeyR(17), CamelliaSubkeyL(16), CamelliaSubkeyR(16),
                 t0, t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(15), CamelliaSubkeyR(15),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(14), CamelliaSubkeyR(14),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(13), CamelliaSubkeyR(13),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(12), CamelliaSubkeyR(12),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(11), CamelliaSubkeyR(11),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(10), CamelliaSubkeyR(10),
                     io[0], io[1], il, ir, t0, t1);

    CAMELLIA_FLS(io[0], io[1], io[2], io[3], CamelliaSubkeyL(9),
                 CamelliaSubkeyR(9), CamelliaSubkeyL(8), CamelliaSubkeyR(8), t0,
                 t1, il, ir);

    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(7), CamelliaSubkeyR(7),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(6), CamelliaSubkeyR(6),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(5), CamelliaSubkeyR(5),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(4), CamelliaSubkeyR(4),
                     io[0], io[1], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[0], io[1], CamelliaSubkeyL(3), CamelliaSubkeyR(3),
                     io[2], io[3], il, ir, t0, t1);
    CAMELLIA_ROUNDSM(io[2], io[3], CamelliaSubkeyL(2), CamelliaSubkeyR(2),
                     io[0], io[1], il, ir, t0, t1);

    /* post whitening but kw4 */
    io[2] ^= CamelliaSubkeyL(0);
    io[3] ^= CamelliaSubkeyR(0);

    t0 = io[0];
    t1 = io[1];
    io[0] = io[2];
    io[1] = io[3];
    io[2] = t0;
    io[3] = t1;

    return;
}

/***
 *
 * API for compatibility
 */

bool Camellia_Ekeygen(const size_t keyBitLength, const uint8_t *rawKey,
                      KEY_TABLE_TYPE keyTable) {
    switch (keyBitLength) {
        case 128:
            camellia_setup128(rawKey, keyTable);
            break;
        case 192:
            camellia_setup192(rawKey, keyTable);
            break;
        case 256:
            camellia_setup256(rawKey, keyTable);
            break;
        default:
            return false;
    }
    return true;
}

bool Camellia_EncryptBlock(const size_t keyBitLength, const uint8_t *plaintext,
                           const KEY_TABLE_TYPE keyTable, uint8_t *cipherText) {
    uint32_t tmp[4];

    tmp[0] = GETU32(plaintext);
    tmp[1] = GETU32(plaintext + 4);
    tmp[2] = GETU32(plaintext + 8);
    tmp[3] = GETU32(plaintext + 12);

    switch (keyBitLength) {
        case 128:
            camellia_encrypt128(keyTable, tmp);
            break;
        case 192:
            /* fall through */
        case 256:
            camellia_encrypt256(keyTable, tmp);
            break;
        default:
            return false;
    }

    PUTU32(cipherText, tmp[0]);
    PUTU32(cipherText + 4, tmp[1]);
    PUTU32(cipherText + 8, tmp[2]);
    PUTU32(cipherText + 12, tmp[3]);

    return true;
}

bool Camellia_DecryptBlock(const size_t keyBitLength, const uint8_t *cipherText,
                           const KEY_TABLE_TYPE keyTable, uint8_t *plaintext) {
    uint32_t tmp[4];

    tmp[0] = GETU32(cipherText);
    tmp[1] = GETU32(cipherText + 4);
    tmp[2] = GETU32(cipherText + 8);
    tmp[3] = GETU32(cipherText + 12);

    switch (keyBitLength) {
        case 128:
            camellia_decrypt128(keyTable, tmp);
            break;
        case 192:
            /* fall through */
        case 256:
            camellia_decrypt256(keyTable, tmp);
            break;
        default:
            return false;
    }
    PUTU32(plaintext, tmp[0]);
    PUTU32(plaintext + 4, tmp[1]);
    PUTU32(plaintext + 8, tmp[2]);
    PUTU32(plaintext + 12, tmp[3]);

    return true;
}

Camellia::Camellia() {
    p_method = enum_crypt_methods_camellia;
    p_blocksize = CAMELLIA_BLOCK_SIZE;

    p_haskey = false;
}

Camellia::~Camellia() {}

const size_t Camellia::BlockSize() { return p_blocksize; }

const size_t Camellia::KeyLength(size_t *min, size_t *max) {
    if (min != nullptr) {
        *min = 16;
    }
    if (max != nullptr) {
        *max = 32;
    }

    return 16;
}

bool Camellia::SetKey(const uint8_t *key, const size_t keylen) {
    p_keylen = keylen;
    memcpy(p_key, key, sizeof(uint8_t) * keylen);
    bool bRet = Camellia_Ekeygen(keylen << 3, key, p_keytable);
    if (bRet) {
        p_haskey = true;
    } else {
        p_haskey = false;
    }

    return bRet;
}

bool Camellia::Encrypt(const uint8_t *plain, uint8_t *cipher) {
    if (!p_haskey) {
        return false;
    }

    return Camellia_EncryptBlock(p_keylen << 3, plain, p_keytable, cipher);
}

bool Camellia::Decrypt(const uint8_t *cipher, uint8_t *plain) {
    if (!p_haskey) {
        return false;
    }

    return Camellia_DecryptBlock(p_keylen << 3, cipher, p_keytable, plain);
}

}
