#pragma once

#include <string>
#include <memory>
#include <functional>
#include <cinttypes>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/basic_socket_acceptor.hpp>

#include "vpncore/logging.hpp"
#include "vpncore/endpoint_pair.hpp"
#include "vpncore/ip_buffer.hpp"

#include "crypto/xchacha20poly1305_crypto.hpp"

namespace avpncore {
	using namespace crypto;
	using boost::asio::ip::tcp;
	namespace http = boost::beast::http;            // from <boost/beast/http.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>

	class vpn_ws_session;
	using vpn_ws_session_ptr = std::shared_ptr<vpn_ws_session>;
	using register_session_handler = std::function<void(endpoint_pair, vpn_ws_session_ptr)>;
	using remove_session_handler = std::function<void(endpoint_pair)>;

	using session2tun_handler = std::function<void(ip_buffer)>;

	static const std::string not_found =
R"(<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.12.2</center>
</body>
</html>
)";

	class vpn_ws_session
		: public std::enable_shared_from_this<vpn_ws_session>
	{
	public:
		vpn_ws_session(tcp::socket socket)
			: m_websocket(std::move(socket))
		{}
		~vpn_ws_session()
		{}

	public:
		void start()
		{
			auto& socket = m_websocket.next_layer();
			http::async_read(socket, m_buffer, m_request,
					std::bind(&vpn_ws_session::on_http_read,
						shared_from_this(), std::placeholders::_1));
		}

		// 将tun数据转发给session.
		void tun2session(const uint8_t* buf, int len)
		{}

		void set_register_handler(register_session_handler handler)
		{
			m_register_session_handler = handler;
		}

		void set_remove_handler(remove_session_handler handler)
		{
			m_remove_session_handler = handler;
		}

		void set_write_ip_handler(session2tun_handler handler)
		{
			m_write_ip_handler = handler;
		}

	private:
		void on_http_read(boost::system::error_code ec)
		{
			if (ec)
			{
				LOG_DBG << "read error: " << ec.message();
				do_close();
				return;
			}

			auto target = m_request.target();
			LOG_DBG << "request target: " << target.to_string();

			auto self = shared_from_this();
			// 如果是http连接, 直接返回 404 页面.
			if (!websocket::is_upgrade(m_request))
			{
				auto res = boost::make_local_shared<http::response<http::string_body>>(
					http::status::not_found, m_request.version());
				res->set(http::field::server, "nginx/1.12.2");
				res->set(http::field::content_type, "text/html");
				res->keep_alive(m_request.keep_alive());
				res->body() = not_found;
				res->prepare_payload();
				auto& socket = m_websocket.next_layer();

				http::async_write(
					socket, *res, [self, res, this]
					(boost::system::error_code, bool) mutable
					{
						do_close();
					});

				return;
			}

			m_websocket.async_accept([self, this]
				(boost::system::error_code ec)
				{
					if (ec)
					{
						LOG_DBG << "websocket async_accept: " << ec.message();
						do_close();
						return;
					}

					do_read();
				});
		}

		void do_read()
		{
			m_websocket.async_read(m_buffer,
				std::bind(&vpn_ws_session::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2));
		}

		void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
		{
			if (ec)
			{
				do_close();
				return;
			}

			//m_request;
			//auto data = boost::asio::buffer_cast<const void*>(m_buffer.data());
			//m_xchacha20poly1305_crypto.decrypt(data, bytes_transferred);

			// 继续读取下一个数据包.
			do_read();
		}

		void do_close()
		{
			// Send a TCP shutdown
			boost::system::error_code ec;
			m_websocket.lowest_layer().shutdown(tcp::socket::shutdown_send, ec);
		}

	private:
		websocket::stream<tcp::socket> m_websocket;
		session2tun_handler m_write_ip_handler;
		endpoint_pair m_endpoint_pair;
		register_session_handler m_register_session_handler;
		remove_session_handler m_remove_session_handler;
		boost::beast::flat_buffer m_buffer;
		http::request<http::string_body> m_request;
		xchacha20poly1305_crypto m_xchacha20poly1305_crypto;
	};

}
