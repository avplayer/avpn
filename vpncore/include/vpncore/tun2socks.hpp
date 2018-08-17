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
#include "vpncore/socks_client.hpp"

namespace avpncore {

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
			, m_dns_index(0)
			, m_udp_socks(io)
			, m_udp_socket(io)
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

			// 启动udp转发socks.
			boost::asio::spawn(m_io_context,
			[this] (boost::asio::yield_context yield) mutable
			{
				using namespace socks;
				boost::system::error_code ec;
				socks_address socks_addr;
				boost::asio::steady_timer timer{ m_io_context };

				while (true)
				{
					if (!connect_socks(yield, m_udp_socks, m_socks_server, socks_addr))
					{
						timer.expires_from_now(std::chrono::minutes(1));
						timer.async_wait(yield[ec]);
						continue;
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
							return;
						}

						// 获取 udp socket 服务器udp转发endpoint.
						m_udp_remote_endp = udpsocks->udp_endpoint();
						LOG_DBG << "* SOCKS5, udp associate: " << m_udp_remote_endp;

						boost::system::error_code ec;
						m_udp_socket.open(m_udp_remote_endp.protocol(), ec);
						m_udp_socket.bind(udp::endpoint(m_udp_remote_endp.protocol(), 0), ec);

						// 开始接收数据.
						for (int i = 0; i < MAX_RECV_BUFFER_SIZE; i++)
						{
							auto& recv_buf = m_udp_recv_buffers[i];
							boost::array<char, 2048>& buf = recv_buf.buffer;
							m_udp_socket.async_receive_from(boost::asio::buffer(buf), recv_buf.endp,
								boost::bind(&tun2socks::socks_handle_udp_read, this,
									i,
									boost::asio::placeholders::error,
									boost::asio::placeholders::bytes_transferred
								)
							);
						}
					});
				}

				keep_udp_socket();
			});

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

		void keep_udp_socket()
		{
			static char tmp[32];
			boost::asio::async_read(m_udp_socks, boost::asio::buffer(tmp, 32),
			[this](const boost::system::error_code& error, std::size_t)
			{
				if (error)
				{
					LOG_DBG << "udp socks is error: " << error.message();
					return;
				}

				// keep udp socket.
				keep_udp_socket();
			});
		}

		void socks_handle_udp_read(int i,
			const boost::system::error_code& error, std::size_t bytes_transferred)
		{
			if (error)
			{
				LOG_DBG << "socks5 udp socks recv error: " << error.message();
				return;
			}

			udp_recv_buffer& recv_buf = m_udp_recv_buffers[i];
			boost::array<char, 2048>& buf = recv_buf.buffer;

			// process socks udp data and write to tun device.
			boost::asio::ip::udp::endpoint src;
			std::string data;

			if (socks::socks_client::udp_unpacket(buf.data(), bytes_transferred, src, data))
			{
				auto ip_len = 28 + data.size();
				ip_buffer buffer(ip_len);

				uint8_t* ip_data = buffer.buf_.get();
				uint8_t* p = ip_data;

				*((uint8_t*)(p + 0)) = 0x45; // version
				*((uint8_t*)(p + 1)) = 0x00; // tos
				*((uint16_t*)(p + 2)) = htons(ip_len); // ip length
				*((uint16_t*)(p + 4)) = htons(ip_len); // id
				*((uint16_t*)(p + 6)) = 0x00;	// flag
				*((uint8_t*)(p + 8)) = 0x30; // ttl
				*((uint8_t*)(p + 9)) = 0x11; // protocol
				*((uint16_t*)(p + 10)) = 0x00; // checksum

				uint32_t src_addr = src.address().to_v4().to_ulong();
				*((uint32_t*)(p + 12)) = htonl(src_addr); // source


				// 是dns.
				bool dns_found = false;
				endpoint_pair pair;
				boost::asio::ip::udp::endpoint local_endp;
				if (src.port() == 53)
				{
					auto dns_id = *(uint16_t*)&data[0];
					auto it = m_dnsmap.find(dns_id);
					if (it != m_dnsmap.end())
					{
						pair = it->second;
						pair.reserve();
						local_endp = boost::asio::ip::udp::endpoint(pair.dst_.address(), pair.dst_.port());
						*((uint32_t*)(p + 16)) = htonl(pair.dst_.address().to_v4().to_ulong()); // local/dest
						dns_found = true;
						m_dnsmap.erase(it);
					}
				}

				// find local endp.
				if (!dns_found)
				{
					uint64_t k = (src_addr << 2) + src.port();
					auto it = m_portmap.find(k);
					if (it != m_portmap.end())
					{
						local_endp = it->second.local_endp;
						pair.src_ = boost::asio::ip::tcp::endpoint(src.address(), src.port());
						pair.dst_ = boost::asio::ip::tcp::endpoint(local_endp.address(), local_endp.port());
						it->second.tick = std::time(nullptr); // update time.
						*((uint32_t*)(p + 16)) = htonl(local_endp.address().to_v4().to_ulong()); // local/dest
					}
					else
					{
						*((uint32_t*)(p + 16)) = 0x00; // local/dest
					}
				}

				*((uint16_t*)(p + 10)) = standard_chksum(p, 20);// htons(sum); // ip header checksum

				// udp header.
				p = p + 20;
				*((uint16_t*)(p + 0)) = htons(src.port()); // source port
				*((uint16_t*)(p + 2)) = htons(local_endp.port()); // dest port
				*((uint16_t*)(p + 4)) = htons(data.size() + 8); // udp len
				*((uint16_t*)(p + 6)) = 0x00; // udp checksum

				// udp body.
				p = p + 8;
				std::memcpy(p, data.data(), data.size());

				// write to device.
				// 计算checksum.
				auto udp_payload = ip_data + 20;
				auto udp_size = ip_len - 20;

				*(uint16_t*)(udp_payload + 6) = udp_chksum_pseudo(udp_payload, udp_size, pair);

				// 写入udp到设备.
				m_demultiplexer->write_udp(buffer);
			}

			// 继续读取下一组udp数据.
			m_udp_socket.async_receive_from(boost::asio::buffer(buf), recv_buf.endp,
				boost::bind(&tun2socks::socks_handle_udp_read, this,
					i,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred
				)
			);
		}

		void handle_udp(ip_buffer buf)
		{
			if (!m_udp_socket.is_open())
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

			auto src_endp = boost::asio::ip::udp::endpoint(src_addr, src_port);
			auto dst_endp = boost::asio::ip::udp::endpoint(dst_addr, dst_port);

			auto ip_len = ntohs(*(uint16_t*)(ip + 2));
			auto udp_len = ntohs(*(uint16_t*)(ip + 24));

			if (buf.len_ != ip_len || udp_len + 20 != buf.len_)
				return;

			if (dst_port == 53)
			{
				auto dns_id = *(uint16_t*)(ip + 28);
				m_dnsmap[dns_id] = endp;
			}
			else
			{
				udp_portmap up;
				up.local_endp = src_endp;
				up.tick = std::time(nullptr);
				auto k = (dst_addr.to_ulong() << 2) + dst_port;
				m_portmap[k] = up;
			}

			auto result = socks::socks_client::udp_packet(dst_endp, ip + 28, udp_len - 8);
			boost::local_shared_ptr<std::string> bufptr = boost::make_local_shared<std::string>(result);
			m_udp_socket.async_send_to(boost::asio::buffer(*bufptr),
				m_udp_remote_endp, [this, bufptr]
				(const boost::system::error_code& error, std::size_t bytes_transferred)
			{
				if (error)
				{
					std::cout << "udp async_send_to error: " << error.message() << std::endl;
					return;
				}

				// nothing to do in here.
			});
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
		uint16_t m_dns_index;
		std::map<uint16_t, endpoint_pair> m_dnsmap;
		boost::asio::ip::tcp::socket m_udp_socks;
		boost::asio::ip::udp::socket m_udp_socket;
		boost::asio::ip::udp::endpoint m_udp_remote_endp;
		// 数据接收缓冲.
		struct udp_recv_buffer
		{
			boost::asio::ip::udp::endpoint endp;
			boost::array<char, 2048> buffer;
		};
		enum { MAX_RECV_BUFFER_SIZE = 712 };
		std::map<int, udp_recv_buffer> m_udp_recv_buffers;

		struct udp_portmap
		{
			std::time_t tick;
			boost::asio::ip::udp::endpoint local_endp;
		};
		std::map<uint64_t, udp_portmap> m_portmap;
	};

}
