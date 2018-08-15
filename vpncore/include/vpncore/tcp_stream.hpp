#pragma once
#include <iostream>
#include <functional>
#include <cstring> // for std::memcpy

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/spawn.hpp>

#include "vpncore/intrusive_ptr_base.hpp"
#include "vpncore/ip_buffer.hpp"
#include "vpncore/endpoint_pair.hpp"
#include "vpncore/logging.hpp"

namespace avpncore {

	// 定义接收到tcp连接请求时的accept handler, 每个tcp连接收到
	// syn将会触发这个handler的调用, 在这个handler中, 需要确认
	// 是否接受或拒绝这个tcp连接, 如果拒绝将会发回一个rst/fin的
	// 数据包, 在这个handler里使用accept函数来确认是否接受这个
	// syn连接请求.
	using accept_handler =
		std::function<void(const boost::system::error_code&)>;

	using closed_handler =
		std::function<void(const boost::system::error_code&)>;

	class tcp_stream
		: public intrusive_ptr_base<tcp_stream>
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

		std::string tcp_state_string(tcp_state s) const
		{
			switch (s)
			{
			case ts_invalid: return "ts_invalid";
			case ts_closed: return "ts_closed";
			case ts_listen: return "ts_listen";
			case ts_syn_sent: return "ts_syn_sent";
			case ts_syn_rcvd: return "ts_syn_rcvd";
			case ts_established: return "ts_established";
			case ts_fin_wait_1: return "ts_fin_wait_1";
			case ts_fin_wait_2: return "ts_fin_wait_2";
			case ts_close_wait: return "ts_close_wait";
			case ts_closing: return "ts_closing";
			case ts_last_ack: return "ts_last_ack";
			case ts_time_wait: return "ts_time_wait";
			}
			return "error tcp state";
		}

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

		// write_ip_packet_handler 用于写入一个ip包
		// 到底层.
		using write_ip_packet_handler = std::function<void(ip_buffer)>;

		tcp_stream(boost::asio::io_context& io_context)
			: m_io_context(io_context)
			, m_accepted(false)
			, m_do_closed(false)
			, m_abort(false)
		{}

		~tcp_stream()
		{
			LOG_DBG << m_endp << " tcp_stream quit!!! leak data: " << m_tcp_recv_buffer.size();
		}

		// 设置各handler.
		void set_accept_handler(accept_handler handler)
		{
			m_accept_handler = handler;
		}

		void set_write_ip_handler(write_ip_packet_handler handler)
		{
			m_write_ip_handler = handler;
		}

		void set_closed_handler(closed_handler handler)
		{
			m_closed_handler = handler;
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
			{
				do_close();
				return;
			}

			m_accepted = true;

			ip_buffer buffer(40, m_endp_reserve);
			auto ip = buffer.data();
			auto tcp = ip + 20;

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
				do_close();
			}
			else
			{
				flags.flag.ack = 1;
				flags.flag.syn = 1;
				flags.flag.rst = 1;
				do_close();
			}

			make_tcp_header(tcp, 20, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 更新为syn包已经发送的状态.
			m_tsm.state_ = tcp_state::ts_syn_sent;

			// 回调写回数据.
			m_write_ip_handler(buffer);
		}

		// 接收底层ip数据.
		void output(const uint8_t* buf, int len)
		{
			auto keep_self = self();
			const uint8_t* p = buf;
			auto last_state = m_tsm.state_;

			uint8_t ihl = ((*(uint8_t*)(p)) & 0x0f) * 4;
			uint16_t total = ntohs(*(uint16_t*)(p + 2));
			uint8_t type = *(uint8_t*)(p + 9);
			uint32_t src_ip =(*(uint32_t*)(p + 12));
			uint32_t dst_ip =(*(uint32_t*)(p + 16));

			if (type != ip_tcp) // only tcp
				return;

			p = p + ihl;

			uint16_t src_port = (*(uint16_t*)(p + 0));
			uint16_t dst_port = (*(uint16_t*)(p + 2));

			if (m_endp.empty())
			{
				endpoint_pair endp(src_ip, src_port, dst_ip, dst_port);
				endp.type_ = type;
				m_endp = endp;
				m_endp_reserve = endp;
				m_endp_reserve.reserve();
			}

			// 下面开始执行tcp状态机, 总体参考下面实现, 稍作修改的地方几个就是这里初始状态设置
			// 为ts_invalid, 而不是closed, 因为这里我需要判断一个tcp stream对象是已经closed
			// 的, 还是新开的等待连接的对象, 另外执行到time_wait时, 按标准需要等待2MSL个时间
			// 再关闭, 在这个时间一直占用, 因为avpn里当一个连接到time_wait状态的时候, 对外实际
			// 是一个连接, 这个连接关闭了并不影响下一次, client使用相同ip:port来向相同server:
			// port发起请求.
			//
			//
			//                              +---------+ ---------\      active OPEN
			//                              |  CLOSED |            \    -----------
			//                              +---------+<---------\   \   create TCB
			//                                |     ^              \   \  snd SYN
			//                   passive OPEN |     |   CLOSE        \   \
			//                   ------------ |     | ----------       \   \
			//                    create TCB  |     | delete TCB         \   \
			//                                V     |                      \   \
			//                              +---------+            CLOSE    |    \
			//                              |  LISTEN |          ---------- |     |
			//                              +---------+          delete TCB |     |
			//                   rcv SYN      |     |     SEND              |     |
			//                  -----------   |     |    -------            |     V
			// +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
			// |         |<-----------------           ------------------>|         |
			// |   SYN   |                    rcv SYN                     |   SYN   |
			// |   RCVD  |<-----------------------------------------------|   SENT  |
			// |         |                    snd ACK                     |         |
			// |         |------------------           -------------------|         |
			// +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
			//   |           --------------   |     |   -----------
			//   |                  x         |     |     snd ACK
			//   |                            V     V
			//   |  CLOSE                   +---------+
			//   | -------                  |  ESTAB  |
			//   | snd FIN                  +---------+
			//   |                   CLOSE    |     |    rcv FIN
			//   V                  -------   |     |    -------
			// +---------+          snd FIN  /       \   snd ACK          +---------+
			// |  FIN    |<-----------------           ------------------>|  CLOSE  |
			// | WAIT-1  |------------------                              |   WAIT  |
			// +---------+          rcv FIN  \                            +---------+
			//   | rcv ACK of FIN   -------   |                            CLOSE  |
			//   | --------------   snd ACK   |                           ------- |
			//   V        x                   V                           snd FIN V
			// +---------+                  +---------+                   +---------+
			// |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
			// +---------+                  +---------+                   +---------+
			//   |                rcv ACK of FIN |                 rcv ACK of FIN |
			//   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
			//   |  -------              x       V    ------------        x       V
			//    \ snd ACK                 +---------+delete TCB         +---------+
			//     ------------------------>|TIME WAIT|------------------>| CLOSED  |
			//                              +---------+                   +---------+


			uint32_t seq = ntohl(*(uint32_t*)(p + 4));
			m_tsm.ack_ = ntohl(*(uint32_t*)(p + 8));
			uint32_t offset = (((*(p + 12)) >> 4) & 0x0f) * 4;
			tcp_flags flags;
			flags.data = *(p + 13);
			uint16_t ws = ntohs(*(uint16_t*)(p + 14));
			uint32_t chksum = ntohl(*(uint32_t*)(p + 16));
			auto payload_len = total - (20 + offset);

			if (flags.flag.syn && m_tsm.state_ != ts_invalid)
			{
				LOG_DBG << m_endp << " unexpected syn, skip it!";
				return;
			}

			m_tsm.win_ = ws;

			// 收到rst强制中断.
			if (flags.flag.rst)
			{
				if (m_tsm.state_ == tcp_state::ts_invalid && m_accept_handler)
				{
					m_accept_handler(boost::asio::error::network_reset);
					m_accept_handler = nullptr;
				}
				m_tsm.state_ = tcp_state::ts_closed;
				LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> flags.flag.rst";
				do_close();
				return;
			}

			bool keep_alive = false;
			// tcp keep alive, only ack.
			if (m_tsm.state_ == tcp_state::ts_established && seq == m_tsm.seq_ - 1)
			{
				LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " tcp keep alive, skip it";
				keep_alive = true;
				return;
			}

			// 记录当前seq.
			m_tsm.seq_ = seq;

			switch (m_tsm.state_)
			{
			case tcp_state::ts_listen:
			case tcp_state::ts_time_wait:
			case tcp_state::ts_closed:
			{
				// 关闭了还发数据过来, rst响应之.
				LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> "
					<< tcp_state_string(m_tsm.state_) << " case ts_listen/ts_time_wait/ts_closed";
				reset();
				return;
			}
			break;
			case tcp_state::ts_invalid:	// 初始状态, 如果不是syn, 则是个错误的数据包, 这里跳过.
			{
				boost::system::error_code ec;
				if (!flags.flag.syn)
				{
					if (m_accept_handler)
					{
						m_accept_handler(boost::asio::error::network_reset);
						m_accept_handler = nullptr;
					}
					reset();
					return;
				}

				m_tsm.state_ = tcp_state::ts_syn_rcvd;	// 更新状态为syn接收到的状态.
				LOG_DBG << m_endp << " " << tcp_state_string(last_state)  << " -> tcp_state::ts_syn_rcvd";

				// 通知用户层接收到连接.
				if (m_accept_handler)
				{
					m_accept_handler(ec);
					m_accept_handler = nullptr;
				}
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
				LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> retransmission tcp_state::ts_syn_rcvd";
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
					LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_established";
				}
			}
			case tcp_state::ts_established:
			{
				// 收到客户端fin, 被动关闭, 发送ack置状态为close_wait, 等待last ack.
				if (flags.flag.fin)
				{
					m_tsm.state_ = tcp_state::ts_close_wait;
					LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_close_wait";
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
					LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_closed";
					m_tsm.state_ = tcp_state::ts_closed;
					do_close();
					// m_tsm.state_ = tcp_state::ts_time_wait;
					need_ack = true;
				}

				// 主动与本地客户端断开, 表示已经向本地客户端发出了fin, 还未收到这个fin的ack.
				if (!flags.flag.ack)
				{
					if (flags.flag.fin)	// 收到fin, 回复ack.
					{
						LOG_DBG << m_endp << " " << tcp_state_string(last_state)  << " -> tcp_state::ts_closing";
						m_tsm.state_ = tcp_state::ts_closing;
						do_close();
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
					LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_fin_wait_2";
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
					LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_closed";
					m_tsm.state_ = tcp_state::ts_closed;
					do_close();
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
				LOG_DBG << m_endp << " " << tcp_state_string(last_state) << " -> tcp_state::ts_closed";
				m_tsm.state_ = tcp_state::ts_closed;
				do_close();
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
			ip_buffer buffer(40, m_endp_reserve);
			auto ip = buffer.data();
			auto tcp = ip + 20;

			flags.data = 0;
			flags.flag.ack = 1;

			m_tsm.lack_ = ack;

			make_tcp_header(tcp, 20, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回调写回ack数据.
			m_write_ip_handler(buffer);
		}

		// 上层发送数据接口.
		int write(const uint8_t* payload, int payload_len)
		{
			if (m_tsm.state_ == tcp_state::ts_invalid ||
				m_tsm.state_ == tcp_state::ts_closed)
				return -1;

			// 计算ip包大小.
			auto iplen = 20 + 20 + payload_len;

			// 回写ack.
			ip_buffer buffer(iplen, m_endp_reserve);
			auto ip = buffer.data();
			auto tcp = ip + 20;

			tcp_flags flags;
			flags.data = 0;
			flags.flag.ack = 1;

			// 复制数据到payload位置.
			std::memcpy(tcp + 20, payload, payload_len);

			make_tcp_header(tcp, 20 + payload_len, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 增加本地seq.
			m_tsm.lseq_ += payload_len;

			// 回调写回ack数据.
			m_write_ip_handler(buffer);

			return payload_len;
		}

		int read(uint8_t* buf, int len)
		{
			len = std::min<int>(len, (int)m_tcp_recv_buffer.size());
			auto bytes = m_tcp_recv_buffer.sgetn((char*)buf, len);
			if ((m_tsm.state_ == tcp_state::ts_invalid ||
				m_tsm.state_ == tcp_state::ts_closed ||
				m_tsm.state_ == tcp_state::ts_close_wait ||
				m_tsm.state_ == tcp_state::ts_closing ||
				m_tsm.state_ == tcp_state::ts_last_ack
				) && bytes == 0)
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
				LOG_DBG << m_endp << " " << tcp_state_string(m_tsm.state_) << " -> tcp_state::ts_fin_wait_1";
				m_tsm.state_ = tcp_state::ts_fin_wait_1;
			}
			else if (m_tsm.state_ == tcp_state::ts_close_wait)
			{
				// 已经收到fin, 发送fin给本地, 并进入ts_last_ack状态.
				LOG_DBG << m_endp << " " << tcp_state_string(m_tsm.state_) << " -> tcp_state::ts_last_ack";
				m_tsm.state_ = tcp_state::ts_last_ack;
			}
			else
			{
				LOG_DBG << m_endp << " " << tcp_state_string(m_tsm.state_) << " -> rst & tcp_state::ts_closed";
				m_tsm.state_ = tcp_state::ts_closed;
				do_close();
				rst = true;
			}

			ip_buffer buffer(40, m_endp_reserve);
			auto ip = buffer.data();
			auto tcp = ip + 20;

			tcp_flags flags;
			flags.data = 0;

			if (rst)
				flags.flag.rst = 1;
			else
				flags.flag.fin = 1;
			flags.flag.ack = 1;
			make_tcp_header(tcp, 20, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 回调写回数据.
			m_write_ip_handler(buffer);
		}

		void reset()
		{
			ip_buffer buffer(40, m_endp_reserve);
			auto ip = buffer.data();
			auto tcp = ip + 20;

			tcp_flags flags;
			flags.data = 0;

			flags.flag.ack = 1;
			flags.flag.rst = 1;
			make_tcp_header(tcp, 20, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

			// 回复ack之后本地seq加1
			m_tsm.lseq_ += 1;

			// 状态置为关闭.
			LOG_DBG << m_endp << " " << tcp_state_string(m_tsm.state_) << " -> rst tcp_state::ts_closed";
			m_tsm.state_ = tcp_state::ts_closed;

			// 回调写回数据.
			m_write_ip_handler(buffer);

			do_close();
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

		void do_close()
		{
			if (m_do_closed)
				return;

			m_do_closed = true;
			boost::system::error_code ec;
			m_closed_handler(ec);
		}

	public:
		boost::asio::io_context& m_io_context;
		endpoint_pair m_endp;
		endpoint_pair m_endp_reserve;
		write_ip_packet_handler m_write_ip_handler;
		accept_handler m_accept_handler;
		closed_handler m_closed_handler;
		boost::asio::streambuf m_tcp_recv_buffer;
		bool m_accepted;
		bool m_do_closed;
		tsm m_tsm;
		bool m_abort;
	};
}
