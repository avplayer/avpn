#pragma once

#include <cinttypes>

#if defined(AVPN_LINUX)
#include <arpa/inet.h> // ntohl etc...
#elif defined(AVPN_WINDOWS)
#include <winsock.h> // ntohl etc...
#endif

#include "vpncore/endpoint_pair.hpp"

namespace avpncore {

	inline uint32_t fold_uint32t(uint32_t c)
	{
		return ((uint32_t)(((c) >> 16) + ((c) & 0x0000ffffUL)));
	}

	inline uint16_t standard_chksum(const uint8_t *dataptr, int len)
	{
		const uint8_t* pb = dataptr;
		const uint16_t* ps = nullptr;
		uint16_t t = 0;
		uint32_t sum = 0;
		int odd = ((uintptr_t)pb & 1);

		/* Get aligned to u16_t */
		if (odd && len > 0) {
			((uint8_t *)&t)[1] = *pb++;
			len--;
		}

		/* Add the bulk of the data */
		ps = (const uint16_t *)(const void *)pb;
		while (len > 1) {
			sum += *ps++;
			len -= 2;
		}

		/* Consume left-over byte, if any */
		if (len > 0) {
			((uint8_t *)&t)[0] = *(const uint8_t *)ps;
		}

		/* Add end bytes */
		sum += t;

		/* Fold 32-bit sum to 16 bits
		calling this twice is probably faster than if statements... */
		sum = fold_uint32t(sum);
		sum = fold_uint32t(sum);

		/* Swap if alignment was odd */
		if (odd) {
			sum = (((sum) & 0xff) << 8) | (((sum) & 0xff00) >> 8);
		}

		return (uint16_t)sum;
	}

	inline uint32_t inet_cksum_pseudo_base(const uint8_t* buf, int len, uint32_t acc)
	{
		int swapped = 0;

		acc += standard_chksum(buf, len);
		acc = fold_uint32t(acc);

		if (len % 2 != 0)
		{
			swapped = !swapped;
			acc = (((acc) & 0xff) << 8) | (((acc) & 0xff00) >> 8);
		}

		if (swapped) {
			acc = (((acc) & 0xff) << 8) | (((acc) & 0xff00) >> 8);
		}

		acc += (uint32_t)htons((uint16_t)0x0006);
		acc += (uint32_t)htons(len);

		/* Fold 32-bit sum to 16 bits
		calling this twice is probably faster than if statements... */
		acc = fold_uint32t(acc);
		acc = fold_uint32t(acc);

		return (uint16_t)~(acc & 0xffffUL);
	}

	inline uint16_t tcp_chksum_pseudo(const uint8_t* buf, int len, const endpoint_pair& endp)
	{
		uint32_t acc;
		uint32_t addr;

		addr = ntohl(endp.src_.address().to_v4().to_uint());
		acc = (addr & 0xffffUL);
		acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));
		addr = ntohl(endp.dst_.address().to_v4().to_uint());
		acc = (uint32_t)(acc + (addr & 0xffffUL));
		acc = (uint32_t)(acc + ((addr >> 16) & 0xffffUL));

		/* fold down to 16 bits */
		acc = fold_uint32t(acc);
		acc = fold_uint32t(acc);

		return inet_cksum_pseudo_base(buf, len, acc);
	}
}