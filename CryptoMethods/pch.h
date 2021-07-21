#pragma once

#ifndef PCH_H
#define PCH_H

#ifdef _MSC_VER
#if (_MSC_VER < 1400)
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <cstdint>
#endif	// _MSC_VER < 1400
#else
#include <cstdint>
#endif	// _MSC_VER

//////////////////////////////////////////////////////////////////////////
// system header
//////////////////////////////////////////////////////////////////////////
#ifdef _WIN32	// Windows
#ifndef _AFX	// without MFC
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif	// WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif	// _AFX
#else	// Unix
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#endif	// _WIN32

//////////////////////////////////////////////////////////////////////////
// C++11 support
//////////////////////////////////////////////////////////////////////////
#if __cplusplus <= 199711L && \
	(!defined(_MSC_VER) || _MSC_VER < 1900) && \
	(!defined(__GNUC__) || \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ < 40603))
#ifndef CXX11_NOT_SUPPORT
#define CXX11_NOT_SUPPORT
#endif	// CXX11_NOT_SUPPORT
#endif	// __cplusplus<=199711L

#ifdef CXX11_NOT_SUPPORT
#define nullptr NULL
#define constexpr const
#define noexcept throw()
#define override
#endif	// CXX11_NOT_SUPPORT

#define _CRYPTOMETHODSDLL_EXPORT_
//#define _CRYPTOMETHODSLIB_EXPORT_

#endif //PCH_H
