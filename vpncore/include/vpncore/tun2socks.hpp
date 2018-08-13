#pragma once

#include <string>
#include <memory>
#include <cinttypes>

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
				m_avpn_acceptor->async_accept(ts,
					std::bind(&tun2socks::accept_handle, this, ts, std::placeholders::_1));
			}

			m_socks_server = socks_server;
			m_avpn_acceptor->start();
			return true;
		}

		void accept_handle(tcp_stream* ts, const boost::system::error_code& ec)
		{
			tcp_stream* new_ts = new tcp_stream(m_io_context);
			m_avpn_acceptor->async_accept(new_ts,
				std::bind(&tun2socks::accept_handle, this, new_ts, std::placeholders::_1));

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
				sc->async_do_proxy(socks_addr, [this, socks_ptr, local, ts, endp]
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
						LOG_DBG << ts->tcp_endpoint_pair() << " read socks " << ec.message();
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

				LOG_DBG << ts->tcp_endpoint_pair() << " read socks total: " << total;
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
						LOG_DBG << ts->tcp_endpoint_pair() << " write local: " << ec.message();
						socks.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
						ts->close();
						break;
					}
					buffer.consume(bytes);
				}

				LOG_DBG << ts->tcp_endpoint_pair() << " read tuntap total: " << total;
			});
		}

	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_dev;
		boost::local_shared_ptr<avpn_acceptor> m_avpn_acceptor;
		std::string m_socks_server;
	};

}
