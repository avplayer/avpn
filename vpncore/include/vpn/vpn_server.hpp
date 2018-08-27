#pragma once

#include <string>
#include <memory>
#include <cinttypes>
#include <functional>
#include <unordered_map>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/basic_socket_acceptor.hpp>

#include "vpncore/logging.hpp"
#include "vpncore/endpoint_pair.hpp"
#include "vpncore/tuntap.hpp"
#include "vpn/vpn_demuxer.hpp"
#include "vpn/vpn_keys.hpp"

namespace avpncore {
	using boost::asio::ip::tcp;
	using tuntap_service::tuntap;

	// session接收到ip包数据, 记录目标和源, 写入到tun.
	// tun读取到ip包, 根据目标和源找到对应session发回远程客户端.
	class vpn_server
	{
		// c++11 noncopyable.
		vpn_server(const vpn_server&) = delete;
		vpn_server& operator=(const vpn_server&) = delete;

	public:
		vpn_server(boost::asio::io_context& io, tuntap& dev, vpn_keys keys,
			unsigned short port, std::string address = "127.0.0.1")
			: m_io_context(io)
			, m_dev(dev)
			, m_server_keys(keys)
			, m_acceptor(io, tcp::endpoint(boost::asio::ip::address::from_string(address), port))
			, m_demuxer(dev)
		{
			m_demuxer.start();

			for (int i = 0; i < 32; i++)
				do_accept();
		}
		~vpn_server()
		{}

	private:
		void do_accept()
		{
			m_acceptor.async_accept([this]
			(boost::system::error_code ec, tcp::socket socket)
			{
				if (ec)
					return;

				// start session.
				m_demuxer.start_session(std::move(socket), m_server_keys);

				// next accept.
				do_accept();
			});
		}

	private:
		boost::asio::io_context& m_io_context;
		tuntap& m_dev;
		vpn_keys m_server_keys;
		tcp::acceptor m_acceptor;
		vpn_demuxer m_demuxer;
	};
}
