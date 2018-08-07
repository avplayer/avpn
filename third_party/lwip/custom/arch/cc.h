/**
 * @file cc.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>
 * 
 * @section LICENSE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LWIP_CUSTOM_CC_H
#define LWIP_CUSTOM_CC_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#ifdef _MSC_VER

#define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACK_STRUCT_END __pragma(pack(pop))
#define PACK_STRUCT_STRUCT

#else

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END
#if defined(__GNUC__) && defined(__MINGW32__)
// Workaround https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
#define PACK_STRUCT_STRUCT __attribute__((packed)) __attribute__((gcc_struct))
#else
#define PACK_STRUCT_STRUCT __attribute__((packed))
#endif

#endif


#define LWIP_PLATFORM_DIAG(x)   do { printf(x); } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("Assertion \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); fflush(NULL); abort(); } while(0)
#define LWIP_ERROR(message, expression, handler) do { if (!(expression)) { \
  printf("Assertion \"%s\" failed at line %d in %s\n", message, __LINE__, __FILE__); \
  fflush(NULL);handler;} } while(0)

#define LWIP_RAND() ( \
    (((uint32_t)(rand() & 0xFF)) << 24) | \
    (((uint32_t)(rand() & 0xFF)) << 16) | \
    (((uint32_t)(rand() & 0xFF)) << 8) | \
    (((uint32_t)(rand() & 0xFF)) << 0) \
)

// for BYTE_ORDER
#if defined(AVPN_USE_WINAPI) && !defined(_MSC_VER)
    #include <sys/param.h>
#elif defined(AVPN_LINUX)
    #include <endian.h>
#elif defined(AVPN_FREEBSD)
    #include <machine/endian.h>
#else
    #define LITTLE_ENDIAN 1234
    #define BIG_ENDIAN 4321
    #if defined(AVPN_LITTLE_ENDIAN)
        #define BYTE_ORDER LITTLE_ENDIAN
    #else
        #define BYTE_ORDER BIG_ENDIAN
    #endif
#endif

#endif
