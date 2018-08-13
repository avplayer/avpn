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
							auto ip_callback = std::bind(&avpn_acceptor::ip_packet,
								shared_from_this(), std::placeholders::_1, std::placeholders::_2);
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

		void remove_stream(const endpoint_pair& pair)
		{
			m_demultiplexer.erase(pair);
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
		struct back_accept
		{
			tcp_stream* stream_;
			accept_handler handler_;
		};
		std::vector<back_accept> m_accept_list;
		std::deque<ip_buffer> m_queue;
		bool m_abort;
	};



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
