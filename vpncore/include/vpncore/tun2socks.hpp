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
#include "vpncore/avpn_acceptor.hpp"
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
		{
		}

	public:
		tcp_stream* make_tcp_stream()
		{
			tcp_stream* ts = new tcp_stream(m_io_context);

			ts->set_closed_handler(
				std::bind(&tun2socks::close_handler, this, ts, std::placeholders::_1));
			ts->set_accept_handler(
				std::bind(&tun2socks::accept_handle, this, ts, std::placeholders::_1));

			return ts;
		}

		bool start(const std::string& local, const std::string& mask,
			const std::string& socks_server)
		{
			m_avpn_acceptor = boost::make_shared<avpn_acceptor>(
				std::ref(m_io_context), std::ref(m_dev));

			for (auto i = 0; i < 40; i++)
			{
				tcp_stream* ts = make_tcp_stream();
				m_tcp_streams[ts] = ts->self();

				m_num_ready++;
				m_avpn_acceptor->async_accept(ts);
			}

			m_socks_server = socks_server;
			m_avpn_acceptor->start();

			// 同时启动定时器.
			start_timer();
			return true;
		}

		void accept_handle(tcp_stream* ts, const boost::system::error_code& ec)
		{
			tcp_stream* new_ts = make_tcp_stream();
			m_tcp_streams[new_ts] = new_ts->self();
			m_avpn_acceptor->async_accept(new_ts);

			LOG_DBG << "current num backlog: " << m_avpn_acceptor->num_backlog();

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

		void close_handler(tcp_stream* ts, const boost::system::error_code& ec)
		{
			LOG_DBG << ts->tcp_endpoint_pair() << " destroy stream.";
			m_avpn_acceptor->remove_stream(ts->tcp_endpoint_pair());
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
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
						break;
					}
					buffer.commit(bytes);
					total += bytes;

					auto p = boost::asio::buffer_cast<const void*>(buffer.data());
					auto ret = ts->write((uint8_t*)p, bytes);
					if (ret < 0)
					{
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
						break;
					}
					buffer.consume(ret);
				}

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
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
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
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
						break;
					}
					buffer.consume(bytes);
				}

				ts->close();
				LOG_DBG << ts->tcp_endpoint_pair() << " 2. read local total: "
					<< total << ", leak data: " << buffer.size();
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
		boost::local_shared_ptr<avpn_acceptor> m_avpn_acceptor;
		std::unordered_map<tcp_stream*, tcp_stream_ptr> m_tcp_streams;
		int m_num_ready;
		int m_num_using;
		std::string m_socks_server;
	};

}
