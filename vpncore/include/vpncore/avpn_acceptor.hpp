#pragma once
#include <memory>
#include <deque>
#include <unordered_map>
#include <functional>

#include <boost/asio/spawn.hpp>

#include <boost/container_hash/hash.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/config.hpp>

#include "vpncore/logging.hpp"

#include "vpncore/endpoint_pair.hpp"
#include "vpncore/chksum.hpp"
#include "vpncore/ip_buffer.hpp"
#include "vpncore/tcp_stream.hpp"

#include "vpncore/tuntap.hpp"
using namespace tuntap_service;


namespace avpncore {

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
		{}

		// 开始工作.
		void start()
		{
 			m_io_context.post(std::bind(
 				&avpn_acceptor::start_work, shared_from_this()));
		}

		void stop()
		{
			m_abort = true;
		}

		void async_accept(tcp_stream* stream)
		{
			m_accept_list.push_back(stream);
		}

		void remove_stream(const endpoint_pair& pair)
		{
			m_demultiplexer.erase(pair);
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
							demuxer = m_accept_list.back();
							m_accept_list.pop_back();
							demuxer->set_write_ip_handler(
								std::bind(&avpn_acceptor::ip_packet, shared_from_this(),
									std::placeholders::_1, std::placeholders::_2));
							m_demultiplexer[endp] = demuxer;
						}
					}
					if (demuxer)
						demuxer->output(buf, bytes);
				}

				buffer.consume(bytes);
			}
		}

		void ip_packet(const endpoint_pair& endp, ip_buffer buffer)
		{
			if (buffer.empty())			// 连接已经销毁, 传过来空包.
			{
				remove_stream(endp);
				return;
			}

			static uint16_t index = 0;

			// 打包ip头.
			uint8_t* p = buffer.data();

			*((uint8_t*)(p + 0)) = 0x45; // version
			*((uint8_t*)(p + 1)) = 0x00; // tos
			*((uint16_t*)(p + 2)) = htons((uint16_t)buffer.len()); // ip length
			*((uint16_t*)(p + 4)) = htons(index++);	// id
			*((uint16_t*)(p + 6)) = 0x00;	// flag
			*((uint8_t*)(p + 8)) = 0x30; // ttl
			*((uint8_t*)(p + 9)) = endp.type_; // protocol
			*((uint16_t*)(p + 10)) = 0x00; // checksum

			*((uint32_t*)(p + 12)) = htonl(endp.src_.address().to_v4().to_ulong()); // source
			*((uint32_t*)(p + 16)) = htonl(endp.dst_.address().to_v4().to_ulong()); // dest

			*((uint16_t*)(p + 10)) = (uint16_t)~(unsigned int)standard_chksum(p, 20);// htons(sum); // ip header checksum

			// 写入tun设备.
			bool write_in_progress = !m_queue.empty();
			m_queue.push_back(buffer);

			if (!write_in_progress)
			{
				boost::asio::spawn(m_io_context, std::bind(
					&avpn_acceptor::write_ip_packet, shared_from_this(), std::placeholders::_1));
			}
		}

		tcp_stream* lookup_stream(const endpoint_pair& endp)
		{
			auto it = m_demultiplexer.find(endp);
			if (it == m_demultiplexer.end())
				return nullptr;
			return it->second;
		}

		endpoint_pair lookup_endpoint_pair(const uint8_t* buf, int len)
		{
			uint8_t ihl = ((*(uint8_t*)(buf)) & 0x0f) * 4;
			uint16_t total = ntohs(*(uint16_t*)(buf + 2));
			uint8_t type = *(uint8_t*)(buf + 9);
			uint32_t src_ip = (*(uint32_t*)(buf + 12));
			uint32_t dst_ip = (*(uint32_t*)(buf + 16));

			if (type == ip_tcp)		// only tcp
			{
				auto p = buf + ihl;

				uint16_t src_port = (*(uint16_t*)(p + 0));
				uint16_t dst_port = (*(uint16_t*)(p + 2));

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
					boost::asio::buffer(p.data(), p.len_), yield[ec]);
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
				m_queue.pop_front();
			}
		}


	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_input;
		std::unordered_map<endpoint_pair, tcp_stream*> m_demultiplexer;
		std::vector<tcp_stream*> m_accept_list;
		std::deque<ip_buffer> m_queue;
		bool m_abort;
	};

}
