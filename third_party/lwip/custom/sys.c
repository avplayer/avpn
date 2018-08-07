/**
 * @file sys.c
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

#include <lwip/sys.h>

#ifdef WIN32
#ifdef _MSC_VER
#pragma warning (push, 3)
#endif

#include <windows.h>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")

#ifdef _MSC_VER
#pragma warning (pop)
#endif

#include <time.h>

static const uint64_t epoch = 116444736000000000L; /* Jan 1, 1601 */
typedef union {
	uint64_t ft_scalar;
#if defined(WIN32) || defined(_WIN32)
	FILETIME ft_struct;
#else
	timeval ft_struct;
#endif
} LWIP_FT;

#endif // WIN32


static uint16_t bytes_reverse16(uint16_t x)
{
	uint16_t y;
	*((uint8_t *)&y + 0) = *((uint8_t *)&x + 1);
	*((uint8_t *)&y + 1) = *((uint8_t *)&x + 0);
	return y;
}

static uint32_t bytes_reverse32(uint32_t x)
{
	uint32_t y;
	*((uint8_t *)&y + 0) = *((uint8_t *)&x + 3);
	*((uint8_t *)&y + 1) = *((uint8_t *)&x + 2);
	*((uint8_t *)&y + 2) = *((uint8_t *)&x + 1);
	*((uint8_t *)&y + 3) = *((uint8_t *)&x + 0);
	return y;
}

static uint64_t bytes_reverse64(uint64_t x)
{
	uint64_t y;
	*((uint8_t *)&y + 0) = *((uint8_t *)&x + 7);
	*((uint8_t *)&y + 1) = *((uint8_t *)&x + 6);
	*((uint8_t *)&y + 2) = *((uint8_t *)&x + 5);
	*((uint8_t *)&y + 3) = *((uint8_t *)&x + 4);
	*((uint8_t *)&y + 4) = *((uint8_t *)&x + 3);
	*((uint8_t *)&y + 5) = *((uint8_t *)&x + 2);
	*((uint8_t *)&y + 6) = *((uint8_t *)&x + 1);
	*((uint8_t *)&y + 7) = *((uint8_t *)&x + 0);
	return y;
}

#if defined(AVPN_LITTLE_ENDIAN)

uint16_t hton16(uint16_t x)
{
	return bytes_reverse16(x);
}

uint32_t hton32(uint32_t x)
{
	return bytes_reverse32(x);
}

uint64_t hton64(uint64_t x)
{
	return bytes_reverse64(x);
}

uint16_t htol16(uint16_t x)
{
	return x;
}

uint32_t htol32(uint32_t x)
{
	return x;
}

uint64_t htol64(uint64_t x)
{
	return x;
}

#elif defined(AVPN_BIG_ENDIAN)

uint16_t hton16(uint16_t x)
{
	return x;
}

uint32_t hton32(uint32_t x)
{
	return x;
}

uint64_t hton64(uint64_t x)
{
	return x;
}

uint16_t htol16(uint16_t x)
{
	return bytes_reverse16(x);
}

uint32_t htol32(uint32_t x)
{
	return bytes_reverse32(x);
}

uint64_t htol64(uint64_t x)
{
	return bytes_reverse64(x);
}

#endif

int64_t gettime()
{
#if defined(WIN32) || defined(_WIN32)
	static int64_t system_start_time = 0;
	static int64_t system_current_time = 0;
	static uint32_t last_time = 0;

	DWORD tmp = timeGetTime();

	if (system_start_time == 0) {
		LWIP_FT nt_time;
		GetSystemTimeAsFileTime(&(nt_time.ft_struct));
		int64_t tim = (int64_t)((nt_time.ft_scalar - epoch) / 10000i64);
		system_start_time = tim - tmp;
	}

	system_current_time += (tmp - last_time);
	last_time = tmp;
	return system_start_time + system_current_time;
#elif defined(__linux__)
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((int64_t)tv.tv_sec * 1000000 + tv.tv_usec) / 1000;
#endif
}

u32_t sys_now (void)
{
    return (u32_t)gettime();
}
