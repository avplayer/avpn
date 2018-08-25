#pragma once

#include <string>
#include <memory>
#include <cinttypes>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "vpncore/logging.hpp"
#include "vpncore/tuntap.hpp"
#include "vpncore/demultiplexer.hpp"
#include "vpncore/tcp_stream.hpp"
#include "tun2socks/socks_client.hpp"

namespace avpncore {
	using boost::asio::ip::tcp;

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

	typedef boost::intrusive_ptr<tcp_stream> tcp_stream_ptr;

	class tun2socks
	{
	public:
		tun2socks(boost::asio::io_context& io, tuntap& dev, std::string dns = "")
			: m_io_context(io)
			, m_dev(dev)
			, m_num_ready(0)
			, m_num_using(0)
			, m_udp_socks_ready(false)
			, m_udp_socks(io)
		{
		}

	public:
		tcp_stream* make_tcp_stream()
		{
			tcp_stream* ts = new tcp_stream(m_io_context);

			ts->set_closed_handler(
				std::bind(&tun2socks::handle_close, this, ts, std::placeholders::_1));
			ts->set_accept_handler(
				std::bind(&tun2socks::handle_accept, this, ts, std::placeholders::_1));

			return ts;
		}

		bool start(const std::string& local, const std::string& mask,
			const std::string& socks_server)
		{
			m_demultiplexer = boost::make_shared<demultiplexer>(
				std::ref(m_io_context), std::ref(m_dev));

			m_demultiplexer->accept_udp(std::bind(&tun2socks::handle_udp,
				this, std::placeholders::_1));

			for (auto i = 0; i < 40; i++)
			{
				tcp_stream* ts = make_tcp_stream();
				m_tcp_streams[ts] = ts->self();

				m_num_ready++;
				m_demultiplexer->async_accept(ts);
			}

			m_socks_server = socks_server;
			m_demultiplexer->start();
			start_udp_socks();

			// 同时启动定时器.
			start_timer();
			return true;
		}

		void handle_accept(tcp_stream* ts, const boost::system::error_code& ec)
		{
			tcp_stream* new_ts = make_tcp_stream();
			m_tcp_streams[new_ts] = new_ts->self();
			m_demultiplexer->async_accept(new_ts);

			LOG_DBG << "current num backlog: " << m_demultiplexer->num_backlog();

			if (ec)
			{
				LOG_DBG << ts->tcp_endpoint_pair() << " accept error: " << ec.message();
				return;
			}

			auto self = ts->self();

			boost::asio::spawn(m_io_context,
			[this, ts, self]
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
					LOG_DBG << "* SOCKS5, can't connect to server: " << ts->tcp_endpoint_pair();
					ts->accept(tcp_stream::ac_deny);
					return;
				}

				// read addresses
				boost::asio::ip::address local;
				auto endp = ts->tcp_endpoint_pair();
				local = endp.dst_.address();

				LOG_DBG << "* SOCKS5, " << ts->tcp_endpoint_pair()
					<< " do socks5 handshake!";

				boost::system::error_code ignore_ec;
				socks.set_option(tcp::no_delay(true), ignore_ec);

				// 配置参数.
				socks_addr.proxy_hostname = false;
				socks_addr.proxy_address = local.to_string();
				socks_addr.proxy_port = std::to_string(endp.dst_.port());
				socks_addr.udp_associate = false;

				// 执行代理异步连接操作.
				auto sc = boost::make_local_shared<socks::socks_client>(boost::ref(socks));
				sc->async_do_proxy(socks_addr, [this, socks_ptr, local, ts, self, endp]
				(const boost::system::error_code& err)
				{
					if (err)
					{
						LOG_DBG << "* SOCKS5, " << ts->tcp_endpoint_pair()
							<< " fail to handshake!";
						ts->accept(tcp_stream::ac_deny);
						return;
					}

					ts->accept(tcp_stream::ac_allow);

					LOG_DBG << "* SOCKS5, " << ts->tcp_endpoint_pair()
						<< " successed to handshake!";

					run(socks_ptr, ts);
				});
			});
		}

		void handle_close(tcp_stream* ts, const boost::system::error_code& ec)
		{
			LOG_DBG << ts->tcp_endpoint_pair() << " destroy stream.";
			m_demultiplexer->remove_stream(ts->tcp_endpoint_pair());
			m_tcp_streams.erase(ts);
		}

	protected:
		void run(boost::shared_ptr<boost::asio::ip::tcp::socket> socks_ptr, tcp_stream* ts)
		{
			auto self = ts->self();
			boost::asio::spawn([this, self, ts, socks_ptr]
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
						LOG_DBG << ts->tcp_endpoint_pair() << " read socks " << ec.message();
						break;
					}
					buffer.commit(bytes);
					total += bytes;

					auto p = boost::asio::buffer_cast<const void*>(buffer.data());
					auto ret = ts->write((uint8_t*)p, bytes);
					if (ret < 0)
					{
						break;
					}
					buffer.consume(ret);
				}

				socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
				ts->close();
				LOG_DBG << ts->tcp_endpoint_pair() << " 1. read socks total: "
					<< total << ", leak data: " << buffer.size();
			});

			boost::asio::spawn([this, self, ts, socks_ptr]
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
					{
						break;
					}

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
						LOG_DBG << ts->tcp_endpoint_pair() << " write socks: " << ec.message();
						break;
					}
					buffer.consume(bytes);
				}

				socks.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
				ts->close();
				LOG_DBG << ts->tcp_endpoint_pair() << " 2. read local total: "
					<< total << ", leak data: " << buffer.size();
			});
		}

		void start_udp_socks()
		{
			boost::asio::spawn(m_io_context,
			[this](boost::asio::yield_context yield) mutable
			{
				using namespace socks;
				boost::system::error_code ec;
				socks_address socks_addr;
				boost::asio::steady_timer timer{ m_io_context };
				m_udp_socks_ready = false;
				m_udp_socks.close(ec);
				if (!connect_socks(yield, m_udp_socks, m_socks_server, socks_addr))
				{
					timer.expires_from_now(std::chrono::seconds(5));
					timer.async_wait(yield[ec]);
					start_udp_socks();
					return;
				}

				boost::system::error_code ignore_ec;
				m_udp_socks.set_option(tcp::no_delay(true), ignore_ec);

				// 配置参数.
				socks_addr.proxy_hostname = false;
				socks_addr.proxy_address = "0.0.0.0";
				socks_addr.proxy_port = std::to_string(m_udp_socks.remote_endpoint().port());
				socks_addr.udp_associate = true;

				auto udpsocks = boost::make_local_shared<socks::socks_client>(std::ref(m_udp_socks));
				udpsocks->async_do_proxy(socks_addr,
				[this, udpsocks](const boost::system::error_code& err)
				{
					if (err)
					{
						LOG_ERR << "socks async_do_proxy udp error: " << err.message();
						start_udp_socks();
						return;
					}

					m_udp_socks_ready = true;
					m_buffer.clear();
					LOG_INFO << "* SOCKS udp over tcp proxy successed!";

					// 开始读取socks server的udp发回的数据.
					boost::asio::spawn(m_io_context,
					[this](boost::asio::yield_context yield) mutable
					{
						udp_read_handle(yield);
					});
				});
			});
		}

		void udp_read_handle(boost::asio::yield_context yield)
		{
			boost::system::error_code ec;
			boost::asio::streambuf buffer;
			boost::asio::steady_timer timer{ m_io_context };
			std::size_t bytes_transferred;

			while (true)
			{
				if (buffer.size() < 16)
				{
					bytes_transferred = boost::asio::async_read(m_udp_socks,
						buffer.prepare(2048), boost::asio::transfer_at_least(16), yield[ec]);
					if (ec)
					{
						m_udp_socks_ready = false;
						timer.expires_from_now(std::chrono::seconds(5));
						timer.async_wait(yield[ec]);
						start_udp_socks();
						return;
					}
					buffer.commit(bytes_transferred);
				}

				tcp::endpoint src;
				tcp::endpoint dst;
				uint16_t payload_len = 0;
				socks::parse_udp_proxy_header(boost::asio::buffer_cast<const void*>(buffer.data()),
					bytes_transferred, src, dst, payload_len);

				LOG_INFO << "udp header, src: " << src << ", dst: " << dst
					<< ", udp size: " << payload_len;

				buffer.consume(16);
				if (buffer.size() < payload_len)
				{
					bytes_transferred = boost::asio::async_read(m_udp_socks, buffer.prepare(payload_len),
						boost::asio::transfer_at_least(payload_len), yield[ec]);
					if (ec)
					{
						timer.expires_from_now(std::chrono::seconds(5));
						timer.async_wait(yield[ec]);
						start_udp_socks();
						return;
					}
					buffer.commit(bytes_transferred);
				}

				write_udp_to_local(boost::asio::buffer_cast<const void*>(buffer.data()),
					payload_len, src, dst);

				buffer.consume(payload_len);
			}
		}

		void write_udp_to_local(const void* buf,
			std::size_t len, const tcp::endpoint& src, const tcp::endpoint& dst)
		{
			auto ip_len = 28 + len;
			ip_buffer buffer(ip_len);
			buffer.endp_.dst_ = src;
			buffer.endp_.src_ = dst;
			buffer.endp_.type_ = ip_udp;

			uint8_t* ip_data = buffer.buf_.get();
			uint8_t* p = ip_data;

			*((uint8_t*)(p + 0)) = 0x45; // version
			*((uint8_t*)(p + 1)) = 0x00; // tos
			*((uint16_t*)(p + 2)) = htons(ip_len); // ip length
			*((uint16_t*)(p + 4)) = 0; // id
			*((uint16_t*)(p + 6)) = 0x00;	// flag
			*((uint8_t*)(p + 8)) = 0x30; // ttl
			*((uint8_t*)(p + 9)) = 0x11; // protocol
			*((uint16_t*)(p + 10)) = 0x00; // checksum

			*((uint32_t*)(p + 12)) = htonl(dst.address().to_v4().to_uint()); // source
			*((uint32_t*)(p + 16)) = htonl(src.address().to_v4().to_uint()); // dest

			// *((uint16_t*)(p + 10)) = standard_chksum(p, 20);// htons(sum); // ip header checksum

			// udp header.
			p = p + 20;
			*((uint16_t*)(p + 0)) = ntohs(dst.port()); // source port
			*((uint16_t*)(p + 2)) = ntohs(src.port()); // dest port
			*((uint16_t*)(p + 4)) = ntohs(len + 8); // udp len
			*((uint16_t*)(p + 6)) = 0x00; // udp checksum

			// udp body.
			p = p + 8;
			std::memcpy(p, buf, len);

			// write to device.
			// 计算checksum.
			auto udp_payload = ip_data + 20;
			auto udp_size = ip_len - 20;

			*((uint16_t*)(udp_payload + 6)) = udp_chksum_pseudo(udp_payload, len + 8, buffer.endp_);

			// 写入udp到设备.
			m_demultiplexer->write_udp(buffer);
		}

		void handle_udp(ip_buffer buf)
		{
			if (!m_udp_socks.is_open() || !m_udp_socks_ready)
				return;

			auto& endp = buf.endp_;

			uint8_t* ip = buf.buf_.get();
			uint8_t ip_version = (ip[0] >> 4);
			if (ip_version != 4)
				return;

			if (buf.len_ < 28 || ip[9] != 0x11)
				return;

			// 转发数据给socks5服务器.
			auto p = ip + 12;
			auto src_addr = boost::asio::ip::address_v4(ntohl(*(uint32_t*)p));
			auto dst_addr = boost::asio::ip::address_v4(ntohl(*(uint32_t*)(p + 4)));
			p = ip + 20;

			uint16_t src_port = ntohs(*(uint16_t*)p);
			uint16_t dst_port = ntohs(*(uint16_t*)(p + 2));

			auto src_endp = tcp::endpoint(src_addr, src_port);
			auto dst_endp = tcp::endpoint(dst_addr, dst_port);

			auto ip_len = ntohs(*(uint16_t*)(ip + 2));
			auto udp_len = ntohs(*(uint16_t*)(ip + 24));

			if (buf.len_ != ip_len || udp_len + 20 != buf.len_)
				return;

			auto payload_len = udp_len - 8;
			auto proxy_header = socks::make_udp_proxy_header(src_endp, dst_endp, payload_len);

			std::string udp_payload(payload_len + 16, '\0');
			std::memcpy((void*)udp_payload.data(), proxy_header.data(), 16);
			std::memcpy((void*)(udp_payload.data() + 16), ip + 28, payload_len);

			LOG_INFO << "write udp, src: " << src_endp << ", dst: " << dst_endp
				<< ", size: " << udp_payload.size();
			write_udp_to_remote(udp_payload);
		}

		void write_udp_to_remote(const std::string& payload)
		{
			auto writing = !m_buffer.empty();
			m_buffer.push_back(payload);
			if (!writing)
			{
				boost::asio::async_write(m_udp_socks, boost::asio::buffer(m_buffer.front()),
					boost::bind(&tun2socks::write_udp_to_remote_handle, this,
						boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
			}
		}

		void write_udp_to_remote_handle(const boost::system::error_code &error, std::size_t bytes_transferred)
		{
			if (error)
			{
				LOG_INFO << "write_udp_to_remote_handle: error: " << error.message();
				return;
			}

			m_buffer.pop_front();

			// 没有数据了, 退出发送.
			if (m_buffer.empty())
				return;

			boost::asio::async_write(m_udp_socks, boost::asio::buffer(m_buffer.front()),
				boost::bind(&tun2socks::write_udp_to_remote_handle, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
		}

		void timer()
		{
			// check tcp stream status etc.
			LOG_DBG << "current tcp stream: " << m_tcp_streams.size();
		}

		void start_timer()
		{
			m_timer.expires_from_now(std::chrono::seconds(1));
			m_timer.async_wait([this](const boost::system::error_code& ec)
			{
				if (ec)
					return;

				start_timer();
				timer();
			});
		}

	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_dev;
		boost::asio::steady_timer m_timer{ m_io_context };
		boost::local_shared_ptr<demultiplexer> m_demultiplexer;
		std::unordered_map<tcp_stream*, tcp_stream_ptr> m_tcp_streams;
		int m_num_ready;
		int m_num_using;
		std::string m_socks_server;
		std::deque<std::string> m_buffer;
		bool m_udp_socks_ready;
		tcp::socket m_udp_socks;
	};

}
