#pragma once

#include <memory>
#include <cinttypes>

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include "vpncore/endpoint_pair.hpp"
#include "vpncore/logging.hpp"

namespace avpncore {

	// 定义IP包数据缓存结构, 这个结构允许
	// 自己管理自己的内存, 使用 boost::local_shared_ptr 来管理
	// 内存资源, 主要是这里不需要考虑线程安全, 避免原子操作.
	// 因为avpn的为异步设计, 整个avpncore程序总是运行在一个线程中
	// 类似于nodejs, 但并不表示做不到多线程.
	// 支持多线程需要实现一个线程安全的ip包分离, 然后将不同tcp
	// 连接的ip包通过线程安全的方式给到tcp stream中, 同样 tcp stream
	// 也需要一个线程安全的方式将组好的ip包回传到ip包分离器.
	// 实践证明, 纯io而非大量cpu密集计算对多线程的需求并不大, 反而
	// 容易因为多线程的调度以及线程安全上锁等导致io效率降低.
	// avpn恰好是一个纯io而大量cpu密集计算的程序.
	struct ip_buffer
	{
		ip_buffer()
			: len_(-1)
		{}

		ip_buffer(int len)
			: buf_(new uint8_t[len])
			, len_(len)
		{}

		ip_buffer(int len, endpoint_pair& endp)
			: buf_(new uint8_t[len])
			, len_(len)
			, endp_(endp)
		{}

		void assign(const uint8_t* p, int len)
		{
			buf_.reset(new uint8_t[len]);
			std::memcpy(buf_.get(), p, len);
			len_ = len;
		}

		void attach(uint8_t* p, int len)
		{
			buf_.reset(p);
			len_ = len;
		}

		uint8_t* data() const
		{
			return buf_.get();
		}

		int len() const
		{
			return len_;
		}

		bool empty() const
		{
			if (len_ <= 0 || !buf_)
				return true;
			return false;
		}

		boost::local_shared_ptr<uint8_t> buf_;
		int len_;
		endpoint_pair endp_;
	};


}
