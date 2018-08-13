#pragma once
#include <memory>
#include <deque>
#include <unordered_map>


#include <boost/asio/spawn.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>

#include <boost/container_hash/hash.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/buffers.hpp>
#include <boost/static_assert.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/config.hpp>

#include "tuntap.hpp"
using namespace tuntap_service;


namespace avpncore {

	struct endpoint_pair
	{
		boost::asio::ip::tcp::endpoint src_;
		boost::asio::ip::tcp::endpoint dst_;

		int type_;

		endpoint_pair()
			: type_(-1)
		{}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(uint32_t src_ip, uint16_t src_port,
			uint32_t dst_ip, uint16_t dst_port)
			: type_(-1)
		{
			src_.address(boost::asio::ip::address_v4(ntohl(src_ip)));
			src_.port(ntohs(src_port));
			dst_.address(boost::asio::ip::address_v4(ntohl(dst_ip)));
			dst_.port(ntohs(dst_port));
		}

		bool empty() const
		{
			return type_ < 0;
		}

		void reserve()
		{
			auto tmp = src_;
			src_ = dst_;
			dst_ = tmp;
		}

		std::string to_string()
		{
			std::ostringstream oss;
			oss << src_ << " - " << dst_;
			return oss.str();
		}
	};

	bool operator==(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ == rh.src_ && lh.dst_ == rh.dst_)
			return true;
		return false;
	}

	bool operator!=(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ != rh.src_ || lh.dst_ != rh.dst_)
			return true;
		return false;
	}

	bool operator<(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ < rh.src_)
			return true;

		if (lh.src_ != rh.src_)
			return false;

		if (lh.dst_ < rh.dst_)
			return true;

		return false;
	}

	bool operator>(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (rh < lh)
			return true;
		if (lh == rh)
			return false;
		return true;
	}
}

namespace std
{
	template<> struct hash<boost::asio::ip::tcp::endpoint>
	{
		typedef boost::asio::ip::tcp::endpoint argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& s) const
		{
			std::string temp = s.address().to_string();
			std::size_t seed = 0;
			boost::hash_combine(seed, temp);
			boost::hash_combine(seed, s.port());
			return seed;
		}
	};

	template<> struct hash<avpncore::endpoint_pair>
	{
		typedef avpncore::endpoint_pair argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& s) const
		{
			result_type const h1(std::hash<boost::asio::ip::tcp::endpoint>{}(s.src_));
			result_type const h2(std::hash<boost::asio::ip::tcp::endpoint>{}(s.dst_));
			std::size_t seed = 0;
			boost::hash_combine(seed, h1);
			boost::hash_combine(seed, h2);
			return seed;
		}
	};
}

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

	typedef std::pair<uint8_t*, int> buffer_pair;

	inline buffer_pair make_buffer_pair(uint8_t* buf, int len)
	{
		buffer_pair pair;
		pair.first = buf;
		pair.second = len;
		return pair;
	}

	inline void free_buffer_pair(buffer_pair& pair)
	{
		if (pair.first)
		{
			delete pair.first;
			pair.first = nullptr;
		}
		pair.second = 0;
	}

	using accept_handler =
		boost::function<void(const boost::system::error_code&)>;

	class tcp_stream
	{
		enum tcp_state
		{
			ts_invalid = -1,
			ts_closed = 0,
			ts_listen = 1,
			ts_syn_sent = 2,
			ts_syn_rcvd = 3,
			ts_established = 4,
			ts_fin_wait_1 = 5,
			ts_fin_wait_2 = 6,
			ts_close_wait = 7,
			ts_closing = 8,
			ts_last_ack = 9,
			ts_time_wait = 10
		};

		union tcp_flags {
			struct unamed_struct
			{
				bool fin : 1;
				bool syn : 1;
				bool rst : 1;
				bool psh : 1;
				bool ack : 1;
				bool urg : 1;
				bool ece : 1;
				bool cwr : 1;
			} flag;
			uint8_t data;
		};

		struct tsm	// tcp state machine
		{
			tsm()
				: state_(ts_invalid)
				, seq_(0)
				, ack_(0)
				, win_(0)
				, lseq_(0)
				, lack_(0)
				, lwin_(0)
			{}

			tcp_state state_;
			uint32_t seq_;
			uint32_t ack_;	// 对端发过来的ack,用来确认是否丢包, 这里不存在丢包所以不用处理.
			uint32_t win_;

			uint32_t lseq_;	// 随本端数据 发送而增大.
			uint32_t lack_;	// 最后回复的ack, 是seq+收到的数据的大小.
			uint32_t lwin_;
		};

		int make_tcp_header(const uint8_t* tcp, int len,
			const endpoint_pair& endp,
			int seq, int ack, uint8_t flags)
		{
			*(uint16_t*)(tcp + 0) = ntohs(endp.src_.port());	// src port
			*(uint16_t*)(tcp + 2) = ntohs(endp.dst_.port());	// dst port

			*(uint32_t*)(tcp + 4) = ntohl(seq);	// seq
			*(uint32_t*)(tcp + 8) = ntohl(ack);	// ack

			*(uint8_t*)(tcp + 12) = 0x50;					// offset

			*(uint8_t*)(tcp + 13) = flags;					// flag
			*(uint16_t*)(tcp + 14) = 0xffff;				// ws
			*(uint16_t*)(tcp + 16) = 0;						// chksum
			*(uint16_t*)(tcp + 18) = 0;						// urg

															// calc chksum, 固定长度20字节.
			*(uint16_t*)(tcp + 16) = tcp_chksum_pseudo(tcp, len, endp);

			return 20;
		}

	public:
		using callback_func = boost::function<void(
			const endpoint_pair&, buffer_pair)>;

		tcp_stream(boost::asio::io_context& io_context)
			: m_io_context(io_context)
			, m_accepted(false)
			, m_abort(false)
		{}

		void set_handlers(callback_func cb, accept_handler ah)
		{
			m_callback_func = cb;
			m_accept_handler = ah;	// 如果是连接请求则回调.
		}

		// 当用户收到accept得到它的时候，
		// 并向外发起连接后，将状态给回
		// 本地连接时，设置使用.
		// 本地连接根据设置状态发回本地连接.
		enum accept_state
		{
			ac_allow,
			ac_deny,
			ac_reset,
		};

		void accept(accept_state state)
		{
			if (m_accepted)
				return;
			m_accepted = true;

			auto pair = make_buffer_pair(new uint8_t[40], 40);
			auto ip = pair.first;
			auto tcp = ip + 20;
			auto& rsv = m_endp_reserve;

			tcp_flags flags;
			flags.data = 0;
			int tcp_header_len = 0;

			m_tsm.lack_ = m_tsm.seq_ + 1;

			// 回复syn ack.
			if (state == ac_allow)
			{
				flags.flag.syn = 1;
				flags.flag.ack = 1;
			}
			else if (state == ac_deny)
			{
				flags.flag.syn = 1;
				flags.flag.fin = 1;
			}
			else
			{
				flags.flag.ack = 1;
				flags.flag.syn = 1;
				flags.flag.rst = 1;
			}

			make_tcp_header(tcp, 20, rsv, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 更新为syn包已经发送的状态.
			m_tsm.state_ = tcp_state::ts_syn_sent;

			// 回调写回数据.
			m_callback_func(rsv, pair);
		}

		// 接收底层ip数据.
		void output(const uint8_t* buf, int len)
		{
			const uint8_t* p = buf;

			uint8_t ihl = ((*(uint8_t*)(p)) & 0x0f) * 4;
			uint16_t total = ntohs(*(uint16_t*)(p + 2));
			uint8_t type = *(uint8_t*)(p + 9);
			uint32_t src_ip = /*ntohl*/(*(uint32_t*)(p + 12));
			uint32_t dst_ip = /*ntohl*/(*(uint32_t*)(p + 16));

			if (type != 6/* && type != 0x11*/) // only tcp
				return;

			p = p + ihl;

			uint16_t src_port = /*ntohs*/(*(uint16_t*)(p + 0));
			uint16_t dst_port = /*ntohs*/(*(uint16_t*)(p + 2));

			if (m_endp.empty())
			{
				endpoint_pair endp(src_ip, src_port, dst_ip, dst_port);
				endp.type_ = type;
				m_endp = endp;
				m_endp_reserve = endp;
				m_endp_reserve.reserve();
			}

			// 解析tcp数据, 执行对应的操作.
			// 如果是syn请求.
			
			uint32_t seq = ntohl(*(uint32_t*)(p + 4));
			m_tsm.ack_ = ntohl(*(uint32_t*)(p + 8));
			uint32_t offset = (((*(p + 12)) >> 4) & 0x0f) * 4;
			tcp_flags flags;
			flags.data = *(p + 13);
			uint16_t ws = ntohs(*(uint16_t*)(p + 14));
			uint32_t chksum = ntohl(*(uint32_t*)(p + 16));
			auto payload_len = total - (20 + offset);

			if (flags.flag.syn && m_tsm.state_ != ts_invalid)
				return;

			m_tsm.win_ = ws;

			// 收到rst强制中断.
			if (flags.flag.rst)
			{
				if (m_tsm.state_ != tcp_state::ts_invalid)
					m_tsm.state_ = tcp_state::ts_closed;
				printf("%s recv flags.flag.rst\n", m_endp.to_string().c_str());
				return;
			}

			bool keep_alive = false;
			// tcp keep alive, only ack.
			if (m_tsm.state_ == tcp_state::ts_established && seq == m_tsm.seq_ - 1)
			{
				printf("%s, tcp keep alive, skip it\n", m_endp.to_string().c_str());
				keep_alive = true;
				return;
			}

			// 记录当前seq.
			m_tsm.seq_ = seq;

			switch (m_tsm.state_)
			{
			case tcp_state::ts_closed:
			{
				// 关闭了还发数据过来, rst响应之.
				reset();
				return;
			}
			break;
			case tcp_state::ts_invalid:	// 初始状态, 如果不是syn, 则是个错误的数据包, 这里跳过.
			{
				if (!flags.flag.syn || flags.flag.ack)
					return;

				m_tsm.state_ = tcp_state::ts_syn_rcvd;	// 更新状态为syn接收到的状态.
				printf("%s, tcp_state::ts_syn_rcvd\n", m_endp.to_string().c_str());

				// 通知用户层接收到连接.
				boost::system::error_code ec;
				m_accept_handler(ec);
				return;	// 直接返回, 由用户层确认是否接受连接回复syn ack.
			}
			break;
			case tcp_state::ts_syn_rcvd:
			{
				if (!flags.flag.syn)
				{
					reset();
					return;
				}

				m_tsm.state_ = tcp_state::ts_syn_rcvd;	// 更新状态为syn接收到的状态.
				printf("%s, retransmission tcp_state::ts_syn_rcvd\n", m_endp.to_string().c_str());
				return;
			}
			break;
			case tcp_state::ts_syn_sent: // 这个状态只表示被动回复syn, 而不是主动syn请求.
			{
				// 期望客户端回复ack完成握手, 因为前面已经发了syn ack,
				// 这里收到的不是ack的话, 肯定是出错了, 这里先暂时跳过.
				if (!flags.flag.ack)
				{
					reset();
					return;
				}
				else
				{
					m_tsm.state_ = tcp_state::ts_established;	// 连接建立.
					printf("%s, tcp_state::ts_established\n", m_endp.to_string().c_str());
				}
			}
			case tcp_state::ts_established:
			{
				// 收到客户端fin, 被动关闭, 发送ack置状态为close_wait, 等待last ack.
				if (flags.flag.fin)
				{
					m_tsm.state_ = tcp_state::ts_close_wait;
				}

				// 连接状态中, 只是一个ack包而已, 不用对ack包再ack.
				if (payload_len == 0 && !flags.flag.fin)
				{
					return;
				}
			}
			break;
			case tcp_state::ts_fin_wait_1:		// 表示主动关闭.
			{
				bool need_ack = false;

				// 同时发出fin, 转为状态ts_time_wait, 回复ack, 关闭这个连接.
				if (flags.flag.fin && flags.flag.ack)
				{
					printf("%s, tcp_state::ts_closed\n", m_endp.to_string().c_str());
					m_tsm.state_ = tcp_state::ts_closed;
					// m_tsm.state_ = tcp_state::ts_time_wait;
					need_ack = true;
				}

				// 主动与本地客户端断开, 表示已经向本地客户端发出了fin, 还未收到这个fin的ack.
				if (!flags.flag.ack)
				{
					if (flags.flag.fin)	// 收到fin, 回复ack.
					{
						printf("%s, tcp_state::ts_closing\n", m_endp.to_string().c_str());
						m_tsm.state_ = tcp_state::ts_closing;
						need_ack = true;
					}
					else
					{
						reset();
						return;
					}
				}

				if (!need_ack)
				{
					// 只是收到ack, 转为fin_wait_2, 等待本地客户端的fin.
					printf("%s, tcp_state::ts_fin_wait_2\n", m_endp.to_string().c_str());
					m_tsm.state_ = tcp_state::ts_fin_wait_2;
					return;
				}
			}
			break;
			case tcp_state::ts_fin_wait_2:
			{
				if (!flags.flag.fin)	// 只期望收到fin, 除非有数据, 否则都跳过.
				{
					if (payload_len <= 0)
						return;
				}

				// 收到fin, 发回ack, 并关闭这个连接, 进入2MSL状态.
				if (flags.flag.fin)
				{
					printf("%s, tcp_state::ts_closed\n", m_endp.to_string().c_str());
					m_tsm.state_ = tcp_state::ts_closed;
					// m_tsm.state_ = tcp_state::ts_time_wait;
				}
			}
			break;
			case tcp_state::ts_close_wait:
			{
				// 对方主动关闭.
				// 等待自己发出fin给本地, 这时收到的ack, 只是最后部分半开状态的向
				// 本地发出数据, 本地回复的ack而已, 所以在这里, 只需要简单的跳过.
				if (flags.flag.ack)
					return;

				// 统统跳过, 在自己发没出fin之前, 所有除对数据的ack之外, 全是错误的
				// 数据, 这里可以直接rst掉这个连接.
				reset();
				return;
			}
			break;
			case tcp_state::ts_last_ack:
			case tcp_state::ts_closing:
			{
				if (!flags.flag.ack)
				{
					return;
				}

				// 如果是close_wait, 则表示收到是last ack, 关闭这个连接.
				// 如果是closing, 则表示收到的是fin的ack, 进入2MSL状态.
				printf("%s, tcp_state::ts_closed\n", m_endp.to_string().c_str());
				m_tsm.state_ = tcp_state::ts_closed;
				// m_tsm.state_ = tcp_state::ts_time_wait;
				return;
			}
			break;
			}

			// save tcp payload.
			if (payload_len > 0 && !keep_alive)
			{
				auto payload = buf + 20 + offset;
				auto target = boost::asio::buffer_cast<void*>(
					m_tcp_recv_buffer.prepare(payload_len));
				std::memcpy(target, payload, payload_len);
				m_tcp_recv_buffer.commit(payload_len);
			}

			int ack = m_tsm.seq_ + payload_len;
			if (payload_len == 0)
				ack += 1;

			// 回写ack.
			auto pair = make_buffer_pair(new uint8_t[20 + 20], 40);
			auto ip = pair.first;
			auto tcp = ip + 20;
			auto& rsv = m_endp_reserve;;

			rsv.type_ = type;

			flags.data = 0;
			flags.flag.ack = 1;

			m_tsm.lack_ = ack;

			make_tcp_header(tcp, 20, rsv, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回调写回ack数据.
			m_callback_func(rsv, pair);
		}

		// 发送数据.
		int write(const uint8_t* payload, int payload_len)
		{
			if (m_tsm.state_ == tcp_state::ts_invalid ||
				m_tsm.state_ == tcp_state::ts_closed)
				return -1;

			// 计算ip包大小.
			auto iplen = 20 + 20 + payload_len;

			// 回写ack.
			auto pair = make_buffer_pair(new uint8_t[iplen], iplen);
			auto ip = pair.first;
			auto tcp = ip + 20;
			auto& rsv = m_endp_reserve;;

			rsv.type_ = 6;

			tcp_flags flags;
			flags.data = 0;
			flags.flag.ack = 1;

			// 复制数据到payload位置.
			std::memcpy(tcp + 20, payload, payload_len);

			make_tcp_header(tcp, 20 + payload_len, rsv, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 增加本地seq.
			m_tsm.lseq_ += payload_len;

			// 回调写回ack数据.
			m_callback_func(rsv, pair);

			return payload_len;
		}

		int read(uint8_t* buf, int len)
		{
			len = std::min<int>(len, (int)m_tcp_recv_buffer.size());
			auto bytes = m_tcp_recv_buffer.sgetn((char*)buf, len);
			if ((m_tsm.state_ == tcp_state::ts_invalid ||
				m_tsm.state_ == tcp_state::ts_closed) && bytes == 0)
				return -1;
			return len;
		}

		void close()
		{
			if (m_abort)
				return;

			m_abort = true;

			// 已经关闭了, 不再响应close.
			if (m_tsm.state_ == tcp_state::ts_closed ||
				m_tsm.state_ == tcp_state::ts_invalid)
			{
				return;
			}

			bool rst = false;

			// 连接状态, 主动关闭连接, 发送fin给本地, 并进入fin_wait1状态.
			if (m_tsm.state_ == tcp_state::ts_established)
			{
				printf("%s, tcp_state::ts_fin_wait_1\n", m_endp.to_string().c_str());
				m_tsm.state_ = tcp_state::ts_fin_wait_1;
			}
			else if (m_tsm.state_ == tcp_state::ts_close_wait)
			{
				// 已经收到fin, 发送fin给本地, 并进入ts_last_ack状态.
				printf("%s, tcp_state::ts_last_ack\n", m_endp.to_string().c_str());
				m_tsm.state_ = tcp_state::ts_last_ack;
			}
			else
			{
				printf("%s, rst & tcp_state::ts_closed\n", m_endp.to_string().c_str());
				m_tsm.state_ = tcp_state::ts_closed;
				rst = true;
			}

			auto pair = make_buffer_pair(new uint8_t[40], 40);
			auto ip = pair.first;
			auto tcp = ip + 20;
			auto& rsv = m_endp_reserve;

			rsv.type_ = 6;

			tcp_flags flags;
			flags.data = 0;

			if (rst)
				flags.flag.rst = 1;
			else
				flags.flag.fin = 1;
			flags.flag.ack = 1;
			make_tcp_header(tcp, 20, rsv, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 回调写回数据.
			m_callback_func(rsv, pair);
		}

		void reset()
		{
			auto pair = make_buffer_pair(new uint8_t[40], 40);
			auto ip = pair.first;
			auto tcp = ip + 20;
			auto& rsv = m_endp_reserve;

			rsv.type_ = 6;

			tcp_flags flags;
			flags.data = 0;

			flags.flag.ack = 1;
			flags.flag.rst = 1;
			make_tcp_header(tcp, 20, rsv, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 状态置为关闭.
			printf("%s, rst tcp_state::ts_closed\n", m_endp.to_string().c_str());
			m_tsm.state_ = tcp_state::ts_closed;

			// 回调写回数据.
			m_callback_func(rsv, pair);
		}

		endpoint_pair tcp_endpoint_pair() const
		{
			return m_endp;
		}

		// 返回当前窗口大小.
		int window_size()
		{
			return m_tsm.win_;
		}

	public:
		boost::asio::io_context& m_io_context;
		endpoint_pair m_endp;
		endpoint_pair m_endp_reserve;
		callback_func m_callback_func;
		accept_handler m_accept_handler;
		boost::asio::streambuf m_tcp_recv_buffer;
		bool m_accepted;
		tsm m_tsm;
		bool m_abort;
	};

	// 分析ip流, 根据ip流的 endpoint_pair
	// 转发到对应的tcp流模块.
	// 如果不存在, 则创建对应的模块.
	class avpn_acceptor : public boost::enable_shared_from_this<avpn_acceptor>
	{
		// c++11 noncopyable.
		avpn_acceptor(const avpn_acceptor&) = delete;
		avpn_acceptor& operator=(const avpn_acceptor&) = delete;

	public:
		avpn_acceptor(boost::asio::io_context& io_context,
			tuntap& input)
			: m_io_context(io_context)
			, m_input(input)
			, m_abort(false)
		{}

		~avpn_acceptor()
		{
			for (auto& q : m_queue)
			{
				free_buffer_pair(q);
			}
		}

		// 开始工作.
		void start()
		{
 			m_io_context.post(boost::bind(
 				&avpn_acceptor::start_work, shared_from_this()));
		}

		void stop()
		{
			m_abort = true;
		}

		// async_accept
		void async_accept(tcp_stream* stream, accept_handler handle)
		{
			back_accept item;
			item.stream_ = stream;
			item.handler_ = handle;
			m_accept_list.push_back(item);
		}

	protected:
		void demux_ip_packet(boost::asio::yield_context yield)
		{
			boost::asio::streambuf buffer;
			boost::system::error_code ec;

			while (!m_abort)
			{
				auto bytes = m_input.async_read_some(
					buffer.prepare(64 * 1024), yield[ec]);
				if (ec)
					return;

				buffer.commit(bytes);
				auto buf = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
				auto endp = lookup_endpoint_pair(buf, bytes);

				if (!endp.empty())
				{
					auto demuxer = lookup_stream(endp);
					if (!demuxer)
					{
						if (!m_accept_list.empty())
						{
							auto& back = m_accept_list.back();
							demuxer = back.stream_;
							auto ip_callback = boost::bind(&avpn_acceptor::ip_packet,
								shared_from_this(), _1, _2);
							demuxer->set_handlers(
								ip_callback, back.handler_);
							m_accept_list.pop_back();
							m_demultiplexer[endp] = demuxer;
						}
					}
					if (demuxer)
						demuxer->output(buf, bytes);
				}

				buffer.consume(bytes);
			}
		}

		void ip_packet(const endpoint_pair& endp, buffer_pair buffer)
		{
			if (buffer.second <= 0) // 连接已经销毁.
			{
				remove_stream(endp);
				return;
			}

			// 打包ip头.
			uint8_t* p = buffer.first;

			*((uint8_t*)(p + 0)) = 0x45; // version
			*((uint8_t*)(p + 1)) = 0x00; // tos
			*((uint16_t*)(p + 2)) = htons((uint16_t)buffer.second); // ip length
			*((uint16_t*)(p + 4)) = htons(m_ip_index++);	// id
			*((uint16_t*)(p + 6)) = 0x00;	// flag
			*((uint8_t*)(p + 8)) = 0x30; // ttl
			*((uint8_t*)(p + 9)) = endp.type_; // protocol
			*((uint16_t*)(p + 10)) = 0x00; // checksum

			*((uint32_t*)(p + 12)) = htonl(endp.src_.address().to_v4().to_ulong()); // source
			*((uint32_t*)(p + 16)) = htonl(endp.dst_.address().to_v4().to_ulong()); // dest

			*((uint16_t*)(p + 10)) = (uint16_t)~(unsigned int)standard_chksum(p, 20);// htons(sum); // ip header checksum

			// 写入tun设备.
			auto pair = make_buffer_pair(buffer.first, buffer.second);

			bool write_in_progress = !m_queue.empty();
			m_queue.push_back(pair);

			if (!write_in_progress)
			{
				boost::asio::spawn(m_io_context,
					boost::bind(&avpn_acceptor::write_ip_packet, shared_from_this(), _1));
			}
		}

		tcp_stream* lookup_stream(const endpoint_pair& endp)
		{
			auto it = m_demultiplexer.find(endp);
			if (it == m_demultiplexer.end())
				return nullptr;
			return it->second;
		}

		void remove_stream(const endpoint_pair& pair)
		{
			m_demultiplexer.erase(pair);
		}

		endpoint_pair lookup_endpoint_pair(const uint8_t* buf, int len)
		{
			uint8_t ihl = ((*(uint8_t*)(buf)) & 0x0f) * 4;
			uint16_t total = ntohs(*(uint16_t*)(buf + 2));
			uint8_t type = *(uint8_t*)(buf + 9);
			uint32_t src_ip = /*ntohl*/(*(uint32_t*)(buf + 12));
			uint32_t dst_ip = /*ntohl*/(*(uint32_t*)(buf + 16));

			if (type == 6/* || type == 0x11*/)		// only tcp
			{
				auto p = buf + ihl;
				
				uint16_t src_port = /*ntohs*/(*(uint16_t*)(p + 0));
				uint16_t dst_port = /*ntohs*/(*(uint16_t*)(p + 2));

				endpoint_pair endp(src_ip, src_port, dst_ip, dst_port);
				endp.type_ = type;

				return endp;
			}

			return endpoint_pair();
		}

		void start_work()
		{
			auto self = shared_from_this();
			boost::asio::spawn([self, this]
			(boost::asio::yield_context yield)
			{
				demux_ip_packet(yield);
			});

			boost::asio::spawn([self, this]
			(boost::asio::yield_context yield)
			{
				write_ip_packet(yield);
			});
		}

		void write_ip_packet(boost::asio::yield_context yield)
		{
			boost::asio::steady_timer try_again_timer(m_io_context);

			while (!m_queue.empty())
			{
				boost::system::error_code ec;
				auto p = m_queue.front();
				auto bytes_transferred = m_input.async_write_some(
					boost::asio::buffer(p.first, p.second), yield[ec]);
				if (ec)
					break;
				if (bytes_transferred == 0)
				{
					try_again_timer.expires_from_now(std::chrono::milliseconds(64));
					try_again_timer.async_wait(yield[ec]);
					if (!ec)
						continue;
					break;
				}
				free_buffer_pair(p);
				m_queue.pop_front();
			}
		}


	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_input;
		std::unordered_map<endpoint_pair, tcp_stream*> m_demultiplexer;
		struct back_accept
		{
			tcp_stream* stream_;
			accept_handler handler_;
		};
		std::vector<back_accept> m_accept_list;
		std::deque<buffer_pair> m_queue;
		static int m_ip_index;
		// 写入队列.
		bool m_abort;
	};

	int avpn_acceptor::m_ip_index(0);


	bool connect_socks(boost::asio::yield_context yield, boost::asio::ip::tcp::socket& sock,
		const std::string& socks_uri, socks::socks_address& socks_addr)
	{
		using namespace socks;

		bool ret = parse_url(socks_uri, socks_addr);
		if (!ret)
		{
			return false;
		}

		// resolver socks uri.
		tcp::resolver::query query(socks_addr.host, socks_addr.port);
		tcp::resolver resolver(sock.get_io_context());
		boost::system::error_code ec;

		auto endp = resolver.async_resolve(query, yield[ec]);
		if (ec)
		{
			return false;
		}

		// 先初始化一个socks client连接，并连接到socks server.
		boost::asio::async_connect(sock, endp, yield[ec]);
		if (ec)
		{
			return false;
		}

		return true;
	}

	class tun2socks
	{
	public:
		tun2socks(boost::asio::io_context& io, tuntap& dev, std::string dns = "")
			: m_io_context(io)
			, m_dev(dev)
		{
		}

	public:
		bool start(const std::string& local, const std::string& mask,
			const std::string& socks_server)
		{
			m_avpn_acceptor = boost::make_shared<avpn_acceptor>(
				std::ref(m_io_context), std::ref(m_dev));

			for (auto i = 0; i < 40; i++)
			{
				tcp_stream* ts = new tcp_stream(m_io_context);
				m_avpn_acceptor->async_accept(ts, boost::bind(&tun2socks::accept_handle, this, ts, _1));
			}

			m_socks_server = socks_server;
			m_avpn_acceptor->start();
			return true;
		}

		void accept_handle(tcp_stream* ts, const boost::system::error_code& ec)
		{
			tcp_stream* new_ts = new tcp_stream(m_io_context);
			m_avpn_acceptor->async_accept(new_ts, boost::bind(&tun2socks::accept_handle, this, new_ts, _1));

			boost::asio::spawn(m_io_context,
			[this, ts]
			(boost::asio::yield_context yield) mutable
			{
				using namespace socks;
				socks_address socks_addr;
				boost::shared_ptr<boost::asio::ip::tcp::socket> socks_ptr
					= boost::make_shared<boost::asio::ip::tcp::socket>(boost::ref(m_io_context));
				boost::asio::ip::tcp::socket& socks = *socks_ptr;

				// 连接到socks服务器.
				if (!connect_socks(yield, socks, m_socks_server, socks_addr))
				{
					printf("SOCKS5, can't connect to server: 0x%p, %s\n",
						ts, ts->tcp_endpoint_pair().to_string().c_str());
					ts->accept(tcp_stream::ac_deny);
					return;
				}

				// read addresses
				boost::asio::ip::address local;
				auto endp = ts->tcp_endpoint_pair();
				local = endp.dst_.address();

				printf("SOCKS5, 0x%p want to connent remote: %s:%d\n",
					ts, local.to_string().c_str(), endp.dst_.port());

				boost::system::error_code ignore_ec;
				socks.set_option(tcp::no_delay(true), ignore_ec);

				// 配置参数.
				socks_addr.proxy_hostname = false;
				socks_addr.proxy_address = local.to_string();
				socks_addr.proxy_port = std::to_string(endp.dst_.port());
				socks_addr.udp_associate = false;

				// 执行代理异步连接操作.
				auto sc = boost::make_local_shared<socks::socks_client>(boost::ref(socks));
				sc->async_do_proxy(socks_addr, [this, socks_ptr, local, ts, endp]
				(const boost::system::error_code& err)
				{
					if (err)
					{
						printf("SOCKS5, fail connect: 0x%p, %s\n",
							ts, ts->tcp_endpoint_pair().to_string().c_str());
						ts->accept(tcp_stream::ac_deny);
						return;
					}

					ts->accept(tcp_stream::ac_allow);
					printf("SOCKS5, 0x%p successed to connect: %s:%d\n",
						ts, local.to_string().c_str(), endp.dst_.port());

					run(socks_ptr, ts);
				});
			});
		}

	protected:
		void run(boost::shared_ptr<boost::asio::ip::tcp::socket> socks_ptr, tcp_stream* ts)
		{
			boost::asio::spawn([this, ts, socks_ptr]
			(boost::asio::yield_context yield) mutable
			{
				boost::asio::streambuf buffer;
				boost::system::error_code ec;
				auto& socks = *socks_ptr;
				auto endp = ts->tcp_endpoint_pair();
				int total = 0;
				boost::asio::steady_timer try_again_timer(m_io_context);
				int win = ts->window_size();

				while (true)
				{
					auto current_win = ts->window_size();
					win = std::max(win, current_win);
					auto wait = current_win < (win / 2);
					auto recv_buffer_size = wait ? 0 : 1024;
					if (wait)
					{
						try_again_timer.expires_from_now(std::chrono::milliseconds(1000));
						try_again_timer.async_wait(yield[ec]);
						if (!ec)
							continue;
						break;
					}

					auto bytes = socks.async_read_some(buffer.prepare(recv_buffer_size), yield[ec]);
					if (ec)
					{
						printf("0x%p, read socks addr: %s, error: %s\n",
							ts, endp.to_string().c_str(), ec.message().c_str());
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
						ts->close();
						break;
					}
					buffer.commit(bytes);
					total += bytes;

					auto p = boost::asio::buffer_cast<const void*>(buffer.data());
					auto ret = ts->write((uint8_t*)p, bytes);
					if (ret < 0)
						break;
					buffer.consume(ret);
				}

				printf("0x%p, %s, read socks total: %d\n",
					ts, endp.to_string().c_str(), total);
			});

			boost::asio::spawn([this, ts, socks_ptr]
			(boost::asio::yield_context yield) mutable
			{
				boost::asio::streambuf buffer;
				boost::system::error_code ec;
				auto& socks = *socks_ptr;
				auto endp = ts->tcp_endpoint_pair();
				int total = 0;
				boost::asio::steady_timer try_again_timer(m_io_context);

				while (true)
				{
					auto b = boost::asio::buffer_cast<uint8_t*>(buffer.prepare(1024));
					int len = ts->read(b, 1024);
					if (len < 0)
						break;

					if (len == 0)
					{
						try_again_timer.expires_from_now(std::chrono::milliseconds(64));
						try_again_timer.async_wait(yield[ec]);
						if (!ec)
							continue;
						break;
					}

					buffer.commit(len);

					total += len;

					auto bytes = boost::asio::async_write(socks, buffer, yield[ec]);
					if (ec)
					{
						printf("0x%p, socks local addr: %s, error: %s\n",
							ts, endp.to_string().c_str(), ec.message().c_str());
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
						ts->close();
						break;
					}
					buffer.consume(bytes);
				}

				printf("0x%p, %s, read tuntap total: %d\n",
					ts, endp.to_string().c_str(), total);
			});
		}

	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_dev;
		boost::shared_ptr<avpn_acceptor> m_avpn_acceptor;
		std::string m_socks_server;
	};

}
