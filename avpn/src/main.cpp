#include <iostream>
#include <iterator>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <deque>

#ifdef __linux__
#  include <sys/resource.h>
#  include <systemd/sd-daemon.h>
#elif _WIN32
#  include <fcntl.h>
#  include <io.h>
#  include <Windows.h>
#endif

// #include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/array.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/asio/spawn.hpp>

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/buffers.hpp>
#include <boost/static_assert.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>

#include "lwip/init.h"
#include "lwip/snmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/netifapi.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcpip.h"
#include "netif/etharp.h"
#include "lwip/ip4_frag.h"
#include "lwip/nd6.h"
#include "lwip/ip6_frag.h"

#include "lwip/api.h"
#include "lwip/memp.h"

#include "lwip/tcp.h"
#include "lwip/ip_addr.h"

#include "vpncore/socks_client.hpp"
#include "vpncore/tuntap.hpp"

using namespace tuntap_service;

using namespace boost::asio;

#ifdef AVPN_WINDOWS
namespace win = boost::asio::windows;
#endif

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;


int platform_init()
{
#if defined(WIN32) || defined(_WIN32)
	/* Disable the "application crashed" popup. */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
		SEM_NOOPENFILEERRORBOX);

#if defined(DEBUG) ||defined(_DEBUG)
	//	_CrtDumpMemoryLeaks();
	// 	int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	// 	flags |= _CRTDBG_LEAK_CHECK_DF;
	// 	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	// 	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
	// 	_CrtSetDbgFlag(flags);
#endif

#if !defined(__MINGW32__)
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	_setmode(0, _O_BINARY);
	_setmode(1, _O_BINARY);
	_setmode(2, _O_BINARY);

	/* Disable stdio output buffering. */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Enable minidump when application crashed. */
#elif defined(__linux__)
	rlimit of = { 50000, 100000 };
	if (setrlimit(RLIMIT_NOFILE, &of) < 0)
	{
		perror("setrlimit for nofile");
	}
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
	{
		perror("setrlimit for coredump");
	}
#endif

	return 0;
}


// app -> tap -> lwip -> socks
// socks -> lwip -> tap -> app

using buffer_queue = std::deque<struct pbuf*>;

std::atomic_int client_count(0);

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



class vpn_splice : public std::enable_shared_from_this<vpn_splice>
{
public:
	vpn_splice(boost::asio::io_context& io, tcp_pcb* pcb, int index = 0)
		: m_io_context(io)
		, m_socks(io)
		, m_pcb(pcb)
		, m_vpn_index(index)
		, m_lwip_up(false)
		, m_socks_up(false)
		, m_socks_in(0)
		, m_socks_out(0)
		, m_lwip_in(0)
		, m_lwip_out(0)
		, m_abort(false)
	{
		client_count++;
		printf("splice: 0x%08x, vpn_splice(), total num vpn: %d\n", client_index(), (int)client_count);
	}

	~vpn_splice()
	{
		client_count--;
		close_lwip();
		printf("splice: 0x%08x, ~vpn_splice(), total num vpn: %d\n", client_index(), (int)client_count);
	}

public:
	void run(const std::string& socks_uri)
	{
		m_lwip_up = true;

		tcp_arg(m_pcb, (void*)this);

		// setup handlers
		tcp_err(m_pcb, client_err_func);
		// set client_recv_func.
		tcp_recv(m_pcb, client_recv_func);

		// 开始一个协程, 执行连接socks服务器等相关操作.
		auto self = shared_from_this();
		boost::asio::spawn(m_io_context, [self, this, socks_uri]
		(boost::asio::yield_context yield)
		{
			using namespace socks;
			socks_address socks_addr;

			if (!connect_socks(yield, m_socks, socks_uri, socks_addr))
			{
				close_lwip();

				printf("splice: 0x%08x, SOCKS5, socks server address can't connect!\n",
					client_index());
				return;
			}

			// read addresses
			boost::asio::ip::address local;

			if (IP_IS_V4(&m_pcb->local_ip))
			{
				local = boost::asio::ip::address_v4(
					ntohl(ip4_addr_get_u32(ip_2_ip4(&m_pcb->local_ip))));
			}
			else if (IP_IS_V6(&m_pcb->local_ip))
			{
				local = boost::asio::ip::address_v6::from_string(
					ip6addr_ntoa(ip_2_ip6(&m_pcb->local_ip)));
			}

			printf("splice: 0x%08x, SOCKS5, want to connent remote: %s:%d\n",
				client_index(), local.to_string().c_str(), m_pcb->local_port);

			// 配置参数.
			socks_addr.proxy_hostname = false;
			socks_addr.proxy_address = local.to_string();
			socks_addr.proxy_port = std::to_string(m_pcb->local_port);
			socks_addr.udp_associate = false;

			// 执行代理异步连接操作.
			m_socks_client = boost::make_local_shared<
				socks::socks_client>(boost::ref(m_socks));
			m_socks_client->async_do_proxy(socks_addr,
				[this, self, local](const boost::system::error_code& err)
			{
				if (err)
				{
					printf("splice: 0x%08x, SOCKS5, do socks proxy error: %s\n",
						client_index(), err.message().c_str());

					// waiting until buffered data is sent to lwip
					// close socks once
					close_lwip();
					return;
				}

				printf("splice: 0x%08x, SOCKS5, successed to connect: %s:%d\n",
					client_index(), local.to_string().c_str(), m_pcb->local_port);

				boost::system::error_code ignore_ec;
				m_socks.set_option(tcp::no_delay(true), ignore_ec);

				boost::asio::spawn(m_io_context,
					boost::bind(&vpn_splice::splice_to_lwip, self, _1));
			});
		});
	}
	void stop()
	{}

protected:

	void splice_to_lwip(boost::asio::yield_context yield)
	{
		// set client_sent_func.
		tcp_sent(m_pcb, client_sent_func);

		// set socks is up.
		m_socks_up = true;

		// 驱动转到lwip到socks.
		write_pbuf_to_socks(nullptr);

		boost::asio::streambuf buffer;
		boost::system::error_code ec;
		boost::asio::steady_timer timer(m_io_context);

		m_socks_in = 0;	// 从socks上收到的远程socks服务器的数据.

		while (!m_abort)
		{
			auto bytes = 0;
			if (!ec)
			{
				bytes = m_socks.async_read_some(buffer.prepare(TCP_WND), yield[ec]);

				buffer.commit(bytes);
				m_socks_in += bytes;

				if (ec)
				{
					printf("splice: 0x%08x, socks is close, read size: %d, buffer: %zd, err: %s\n",
						client_index(), m_socks_in, buffer.size(), ec.message().c_str());
				}
			}

			// 遇到lwip已经关闭, 退出转发socks到lwip.
			if (!m_lwip_up)
			{
				m_socks_up = false;

				printf("splice: 0x%08x, lwip is close, socks socket read quit, leak data: %zd\n",
					client_index(), buffer.size());

				// 关闭socks上的读取操作.
				m_socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
				return;
			}

			// sent to lwip.
			do {
				// 获取sndbuf大小, 每次tcp_write不超过这个大小.
				auto to_write = std::min<std::size_t>(buffer.size(), tcp_sndbuf(m_pcb));
				if (to_write == 0)
					break;

				auto buf = boost::asio::buffer_cast<const char*>(buffer.data());
				err_t err = tcp_write(m_pcb, buf, to_write, TCP_WRITE_FLAG_COPY);
				if (err != ERR_OK)
				{
					if (err == ERR_MEM)
						break;

					// abort lwip connection.
					abort_connection();
					return;
				}

				buffer.consume(to_write);
				m_lwip_out += to_write;

			} while (buffer.size() > 0);

			err_t err = tcp_output(m_pcb);
			if (err != ERR_OK)
			{
				std::cout << "tcp_output failed " << err << "\n";
				printf("splice: 0x%08x, tcp_output failed: %d\n", client_index(), err);
				// abort lwip connection.
				abort_connection();
				return;
			}

			if (ec)
			{
				if (buffer.size() != 0) // 继续将数据写入lwip.
				{
					timer.expires_from_now(std::chrono::milliseconds(500));
					timer.async_wait(yield[ec]);
					continue;
				}

				// 停止lwip数据转到到socks, 因为socket已经断开, 无法再转发.
				// 执行到这里，要转发给lwip的缓存已经都转发完了, 其实可以关闭
				// lwip了.
				if (m_lwip_up)
				{
					m_socks_up = false;

					// stop receiving from lwip.
					tcp_recv(m_pcb, NULL);
				}

				return;
			}
		}
	}

	void close_lwip()
	{
		if (!m_lwip_up)
			return;

		printf("splice: 0x%08x, close_lwip!\n", client_index());

		// remove callbacks
		tcp_err(m_pcb, NULL);
		tcp_recv(m_pcb, NULL);
		tcp_sent(m_pcb, NULL);

		m_lwip_up = false;

		err_t err = tcp_close(m_pcb);
		if (err != ERR_OK)
		{
			m_abort = true;
			tcp_abort(m_pcb);
		}
	}

	void abort_connection()
	{
		if (!m_lwip_up)
			return;

		printf("splice: 0x%08x, abort_connection!\n", client_index());

		// remove callbacks
		tcp_err(m_pcb, NULL);
		tcp_recv(m_pcb, NULL);
		tcp_sent(m_pcb, NULL);
		tcp_abort(m_pcb);

		m_lwip_up = false;

		if (m_socks_up && m_socks.is_open())
		{
			// 关闭socks上的读取操作.
			boost::system::error_code ec;
			m_socks.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
		}
	}

	// friend
	static void client_err_func(void *arg, err_t err)
	{
		auto splicer = (vpn_splice*)arg;
		splicer->client_err(err);
	}

	void client_err(err_t err)
	{
		// waiting untill buffered data is sent to SOCKS
		// close lwip once
		m_lwip_up = false;

		if (m_socks_up)
			tcp_recv(m_pcb, NULL);
	}

	// friend
	static err_t client_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
	{
		auto splicer = (vpn_splice*)arg;
		return splicer->client_recv(tpcb, p, err);
	}

	// friend
	static err_t client_sent_func(void *arg, struct tcp_pcb *tpcb, u16_t len)
	{
		auto splicer = (vpn_splice*)arg;
		return splicer->client_sent(tpcb, len);
	}

	err_t client_sent(struct tcp_pcb *tpcb, u16_t len)
	{
		// 如果数据已经发送完了，但socks已经关闭,
		// 则在这里执行 tcp_close 等操作.
		if (!m_socks.is_open())
		{
			printf("splice: 0x%08x, client_sent, socks is closed!\n", client_index());
			close_lwip();
		}

		return ERR_OK;
	}

	err_t client_recv(struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
	{
		if (!p)	// lwip closed.
		{
			// waiting untill buffered data is sent to SOCKS
			// close lwip once
			close_lwip();

			printf("splice: 0x%08x, lwip closed, snd queue: %zd\n",
				client_index(), m_snd_queue.size());

			// 			if (m_socks.is_open())
			// 			{
			// 				boost::system::error_code ec;
			// 				m_socks.shutdown(socket_base::shutdown_both, ec);
			// 			}
			return ERR_OK;
		}

		// send pbuf to socks.
		write_pbuf_to_socks(p);

		return ERR_OK;
	}

	void write_pbuf_to_socks(struct pbuf* p)
	{
		bool write_in_progress = !m_snd_queue.empty();
		if (p)
		{
			// 统计从lwip中获取到的数据.
			m_lwip_in += p->tot_len;
		}

		if (!m_socks_up)
		{
			printf("splice: 0x%08x, socks not up, lwip snd queue size: %zd\n",
				client_index(), m_snd_queue.size());

			if (m_snd_queue.size() > 500)
			{
				BOOST_ASSERT("m_snd_queue.size() > 500" && false);
				printf("splice: 0x%08x, drop packet, lwip snd queue size: %zd\n",
					client_index(), m_snd_queue.size());
				// abort lwip connection.
				abort_connection();
				return;
			}
		}

		if (p)
		{
			m_snd_queue.push_back(p);
		}
		else
		{
			if (write_in_progress)
			{
				p = m_snd_queue.front();
				write_in_progress = false;
			}
			else
			{
				write_in_progress = true;
			}
		}

		if (!write_in_progress && m_socks_up)
		{
			boost::asio::async_write(m_socks,
				boost::asio::buffer(p->payload, p->len),
				boost::asio::transfer_exactly(p->len),
				boost::bind(&vpn_splice::handle_write,
					shared_from_this(), boost::asio::placeholders::error));
		}
	}

	void handle_write(const boost::system::error_code& error)
	{
		if (error)
		{
			// waiting until buffered data is sent to lwip
			// close socks once
			m_socks_up = false;

			printf("splice: 0x%08x, handle_write, error: %s\n",
				client_index(), error.message().c_str());

			// 释放pbuf内存.
			for (auto& q : m_snd_queue)
				pbuf_free(q);
			m_snd_queue.clear();

			return;
		}

		auto p = m_snd_queue.front();
		m_socks_out += p->len;

		if (p->next && p->next->len > 0)
		{
			p = p->next;
		}
		else
		{
			// 释放已发送过的pbuf.
			pbuf_free(p);
			m_snd_queue.pop_front();

			// 取出下一个pbuf, 发送它.
			if (!m_snd_queue.empty())
				p = m_snd_queue.front();
		}

		if (!m_snd_queue.empty())
		{
			boost::asio::async_write(m_socks,
				boost::asio::buffer(p->payload, p->len),
				boost::asio::transfer_exactly(p->len),
				boost::bind(&vpn_splice::handle_write,
					shared_from_this(), boost::asio::placeholders::error));
		}
	}

	int client_index()
	{
		return m_vpn_index;
	}


private:
	boost::asio::io_context& m_io_context;
	boost::asio::ip::tcp::socket m_socks;
	tcp_pcb* m_pcb;
	typedef std::deque<struct pbuf*> vpn_queue;
	vpn_queue m_snd_queue;	// write pbuf to socks quque.
	boost::local_shared_ptr<socks::socks_client> m_socks_client;
	int m_vpn_index;
	bool m_lwip_up;
	bool m_socks_up;
	int m_socks_in;
	int m_socks_out;
	int m_lwip_in;
	int m_lwip_out;
	bool m_abort;
};

class tun2socks
{
public:
	tun2socks(boost::asio::io_context& io, tuntap& dev, std::string dns = "")
		: m_io_context(io)
		, m_strand(io)
		, m_timer(io)
		, m_dev(dev)
		, m_dns_server(dns)
		, m_socket_socks(io)
		, m_udp_socket(io)
		, m_udp_socks_up(false)
		, m_num_clients(0)
	{}
	~tun2socks()
	{}

public:
	bool start(const std::string& local, const std::string& mask,
		const std::string& socks_server)
	{
		m_socks_server = socks_server;
		start_udp_socks();

		//  init lwip.
		lwip_init();

		// make addresses for netif
		ip4_addr_t addr;
		addr.addr = inet_addr(local.c_str());
		ip4_addr_t netmask;
		netmask.addr = inet_addr(mask.c_str());
		ip4_addr_t gw;
		ip4_addr_set_any(&gw);

		memset(&m_netif, 0, sizeof(m_netif));
		if (!netif_add(&m_netif, &addr, &netmask, &gw,
			(void*)this, netif_init_func, netif_input_func))
		{
			return false;
		}

		netif_set_up(&m_netif);
		netif_set_link_up(&m_netif);
		netif_set_pretend_tcp(&m_netif, 1);
		netif_set_default(&m_netif);

		struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
		if (!l)
		{
			return false;
		}

		if (tcp_bind_to_netif(l, "ho0") != ERR_OK)
		{
			tcp_close(l);
			return false;
		}

		tcp_bind_netif(l, &m_netif);

		struct tcp_pcb *listener;
		listener = tcp_listen(l);
		if (!listener)
		{
			tcp_close(l);
			return false;
		}

		// set callback arg.
		tcp_arg(listener, (void*)this);

		// start tcp accept.
		tcp_accept(listener, listener_accept_func);

		// start read device.
		do_read();

		// start timer.
		start_timer(0);

		return true;
	}

private:
	static
		err_t netif_init_func(struct netif *netif)
	{
		std::cout << "netif func init\n";

		netif->name[0] = 'h';
		netif->name[1] = 'o';
		netif->output = netif_output_func;
		netif->output_ip6 = netif_output_ip6_func;

		return ERR_OK;
	}

	// friend
	static err_t netif_output_func(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
	{
		auto pthis = (tun2socks*)netif->state;
		return pthis->common_netif_output(netif, p);
	}

	// friend
	static err_t netif_output_ip6_func(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
	{
		auto pthis = (tun2socks*)netif->state;
		return pthis->common_netif_output(netif, p);
	}

	err_t common_netif_output(struct netif *netif, struct pbuf *p)
	{
		do {
			do_write_pbuf(p);
		} while (p = p->next);

		return ERR_OK;
	}

	static
		err_t netif_input_func(struct pbuf *p, struct netif *inp)
	{
		uint8_t ip_version = 0;
		if (p->len > 0)
		{
			ip_version = (((uint8_t *)p->payload)[0] >> 4);
		}

		switch (ip_version) {
		case 4: {
			// printf("ip_input, pointer: %p, len: %d\n", p->payload, p->len);
			return ip_input(p, inp);
		} break;
		case 6: {
			// 		if (options.netif_ip6addr) {
			// 			return ip6_input(p, inp);
			// 		}
		} break;
		}

		pbuf_free(p);
		return ERR_OK;
	}

	// friend
	static err_t listener_accept_func(void *arg, struct tcp_pcb *newpcb, err_t err)
	{
		auto pthis = (tun2socks*)arg;
		return pthis->listener_accept(arg, newpcb, err);
	}

	err_t listener_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
	{
		m_num_clients++;
		auto splicer = std::make_shared<vpn_splice>(std::ref(m_io_context), newpcb, m_num_clients);
		splicer->run(m_socks_server);

		// socks 上收到数据，往对应的tcp_pcb上发送
		// tcp_pcb 上收到数据，往对应的 socks 上发送
		return ERR_OK;
	}

	void do_write_pbuf(struct pbuf* p)
	{
		bool write_in_progress = !m_buffer_queue.empty();

		if (p)
		{
			m_buffer_queue.push_back(p);
			pbuf_ref(p);
		}

		if (!write_in_progress)
		{
			boost::asio::async_write(m_dev,
				boost::asio::buffer(p->payload, p->len),
				boost::asio::transfer_exactly(p->len),
				boost::asio::bind_executor(m_strand,
					boost::bind(&tun2socks::handle_write, this, boost::asio::placeholders::error)));
		}
	}

	void handle_write(const boost::system::error_code& error)
	{
		if (error)
		{
			for (auto& q : m_buffer_queue)
				pbuf_free(q);

			std::cerr << error.message() << std::endl;
			return;
		}

		auto p = m_buffer_queue.front();
		pbuf_free(p);

		m_buffer_queue.pop_front();
		if (!m_buffer_queue.empty())
		{
			p = m_buffer_queue.front();

			boost::asio::async_write(m_dev,
				boost::asio::buffer(p->payload, p->len),
				boost::asio::transfer_exactly(p->len),
				boost::asio::bind_executor(m_strand,
					boost::bind(&tun2socks::handle_write, this, boost::asio::placeholders::error)));
		}
	}

	void start_udp_socks()
	{
		boost::asio::spawn(m_io_context, [this]
		(boost::asio::yield_context yield)
		{
			using namespace socks;
			socks_address socks_addr;

			if (!connect_socks(yield, m_socket_socks, m_socks_server, socks_addr))
			{
				printf("SOCKS5, socks server address can't connect!\n");

				// stop tun2socks.
				m_io_context.stop();
				return;
			}

			// 开始一个udp转发服务.
			m_udp_socks = boost::make_local_shared<socks::socks_client>(std::ref(m_socket_socks));


			// 配置参数.
			socks_addr.proxy_hostname = false;
			socks_addr.proxy_address = "0.0.0.0";
			socks_addr.proxy_port = std::to_string(m_socket_socks.remote_endpoint().port());
			socks_addr.udp_associate = true;

			m_udp_socks->async_do_proxy(socks_addr,
				[this](const boost::system::error_code& err)
			{
				if (err)
				{
					printf("SOCKS5, async_do_proxy udp error: %s\n", err.message().c_str());
					return;
				}

				m_udp_socks_up = true;

				// 获取 udp socket 服务器udp转发endpoint.
				auto udp_endp = m_udp_socks->udp_endpoint();
				std::cout << "* SOCKS5, udp associate: " << udp_endp << std::endl;

				boost::system::error_code ec;
				m_udp_socket.open(udp_endp.protocol(), ec);
				m_udp_socket.bind(udp::endpoint(udp_endp.protocol(), 0), ec);

				// 开始接收数据.
				for (int i = 0; i < MAX_RECV_BUFFER_SIZE; i++)
				{
					recv_buffer& recv_buf = m_recv_buffers[i];
					boost::array<char, 2048>& buf = recv_buf.buffer;
					m_udp_socket.async_receive_from(boost::asio::buffer(buf), recv_buf.endp,
						boost::bind(&tun2socks::socks_handle_udp_read, this,
							i,
							boost::asio::placeholders::error,
							boost::asio::placeholders::bytes_transferred
						)
					);
				}

				keep_udp_socket();
			});
		});
	}

	void keep_udp_socket()
	{
		static char tmp[32];
		boost::asio::async_read(m_socket_socks, boost::asio::buffer(tmp, 32),
			[this](const boost::system::error_code& error, std::size_t)
		{
			if (error)
			{
				m_udp_socks_up = false;
				printf("SOCKS5, udp socks is error: %s\n", error.message().c_str());
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
			m_udp_socks_up = false;
			printf("SOCKS5, udp socks recv %d error: %s\n", i, error.message().c_str());
			return;
		}

		recv_buffer& recv_buf = m_recv_buffers[i];
		boost::array<char, 2048>& buf = recv_buf.buffer;

		// process socks udp data and write to tun device.
		udp::endpoint src;
		std::string data;

		// 解析udp数据包, 成功后重新打包写入tun device.
		if (m_udp_socks->udp_unpacket(buf.data(), bytes_transferred, src, data))
		{
			auto ip_len = 28 + data.size();
			uint8_t* ip_data = (uint8_t*)mem_malloc(ip_len);
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
			udp::endpoint local_endp;
			if (src.port() == 53)
			{
				auto dns_id = *(uint16_t*)&data[0];
				auto it = m_dnsmap.find(dns_id);
				if (it != m_dnsmap.end())
				{
					local_endp = it->second;
					*((uint32_t*)(p + 16)) = htonl(local_endp.address().to_v4().to_ulong()); // local/dest
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
					it->second.tick = std::time(nullptr); // update time.
					*((uint32_t*)(p + 16)) = htonl(local_endp.address().to_v4().to_ulong()); // local/dest
				}
				else
				{
					*((uint32_t*)(p + 16)) = 0x00; // local/dest
				}
			}

			*((uint16_t*)(p + 10)) = inet_chksum(p, 20);// htons(sum); // ip header checksum

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
			struct pbuf* pb = pbuf_alloc_reference(ip_data, ip_len, PBUF_REF);

			// 计算checksum.
			ip4_addr_t src_addr_t, dst_addr_t;
			src_addr_t.addr = htonl(src_addr);
			dst_addr_t.addr = htonl(local_endp.address().to_v4().to_ulong());

			struct pbuf chk = *pb;
			chk.payload = (uint8_t*)pb->payload + 20;
			chk.tot_len = pb->tot_len - 20;
			chk.len = pb->len - 20;
			*((uint16_t*)((uint8_t*)chk.payload + 6)) = inet_chksum_pseudo(
				&chk, IP_PROTO_UDP, chk.tot_len, &src_addr_t, &dst_addr_t); // checksum

			pb->ref = 0; // 因为do_write_pbuf内部执行了pbuf_ref, 故意减为0.
			do_write_pbuf(pb);
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

	void start_timer(int count)
	{
		// 启动调度定时器.
		m_timer.expires_from_now(std::chrono::milliseconds(250));
		m_timer.async_wait([this, count](const boost::system::error_code& ec) mutable
		{
			if (ec)
				return;

			// schedule next timer.
			start_timer(++count);

			// call the TCP timer function (every 1/4 second)
			tcp_tmr();

			// every second, call other timer functions.
			if (count % 4 == 0)
			{
				time_t current_time;
				struct tm * time_info;
				char timeString[9];  // space for "HH:MM:SS\0"

				time(&current_time);
				time_info = localtime(&current_time);

				strftime(timeString, sizeof(timeString), "%H:%M:%S", time_info);
				printf("%s\n", timeString);

#if IP_REASSEMBLY
				ip_reass_tmr();
#endif

#if LWIP_IPV6
				nd6_tmr();
#endif

#if LWIP_IPV6 && LWIP_IPV6_REASS
				ip6_reass_tmr();
#endif
			}
		});
	}

	void do_read()
	{
		m_dev.async_read_some(m_buffer.prepare(1024 * 64),
			[this](const boost::system::error_code& error, std::size_t bytes_transferred) mutable
		{
			if (error)
			{
				std::cout << "read error, " << error.message() << std::endl;
				return;
			}

			{
				m_buffer.commit(bytes_transferred);

				auto consumer = [this](std::size_t* len) mutable { m_buffer.consume(*len); };
				typedef std::unique_ptr<std::size_t, decltype(consumer)> buffer_consume;
				buffer_consume buffer_consumer(&bytes_transferred, consumer);

				auto tmp = boost::asio::buffer_cast<const void*>(m_buffer.data());
				auto data_len = bytes_transferred;

				// obtain pbuf
				if (data_len > std::numeric_limits<uint16_t>::max())
				{
					std::cout << "device read: packet too large\n";
					return;
				}

				// 如果是udp包, 则按udp包处理
				if (process_udp_packet((uint8_t*)tmp, data_len))
				{
					do_read();
					return;
				}

				struct pbuf *p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(data_len), PBUF_POOL);
				if (!p)
				{
					std::cout << "device read: pbuf_alloc failed\n";
					return;
				}

				// write packet to pbuf
				if (pbuf_take(p, tmp, static_cast<u16_t>(data_len)) != ERR_OK)
				{
					std::cout << "device read: write packet to pbuf failed\n";
					return;
				}

				// pass pbuf to input
				if (m_netif.input(p, &m_netif) != ERR_OK)
				{
					std::cout << "device read: input failed\n";
					pbuf_free(p);
				}
			}

			do_read();
		});
	}

	bool process_udp_packet(uint8_t* data, int data_len)
	{
		uint8_t ip_version = (data[0] >> 4);

		switch (ip_version)
		{
		case 4:
		{
			// udp header size = 28, Protocol = 0x11
			// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
			if (data_len < 28 || data[9] != 0x11)
				return false;

			// https://en.wikipedia.org/wiki/IPv4
			auto p = data + 12; // source address.
								// uint32_t src = ntohl(*(uint32_t*)p);
								// uint32_t dst = ntohl(*(uint32_t*)(p + 4));

			auto src_addr = boost::asio::ip::address_v4(ntohl(*(uint32_t*)p));
			auto dst_addr = boost::asio::ip::address_v4(ntohl(*(uint32_t*)(p + 4)));

			p = data + 20;

			uint16_t src_port = ntohs(*(uint16_t*)p);
			uint16_t dst_port = ntohs(*(uint16_t*)(p + 2));

			auto src_endp = boost::asio::ip::udp::endpoint(src_addr, src_port);
			auto dst_endp = boost::asio::ip::udp::endpoint(dst_addr, dst_port);

			// ip 包大小.
			auto ip_len = ntohs(*(uint16_t*)(data + 2));
			// udp 包大小.
			auto udp_len = ntohs(*(uint16_t*)(data + 24));

			std::cout << "process_udp_packet, src: " << src_endp << ", dst: " << dst_endp
				<< ",ip len: " << ip_len << ", udp len: " << udp_len << std::endl;

			if (data_len != ip_len || udp_len + 20 != data_len)
				return false;

			// 添加映射.
			udp_portmap up;
			up.local_endp = src_endp;
			up.tick = std::time(nullptr);
			auto k = (dst_addr.to_ulong() << 2) + dst_port;
			m_portmap[k] = up;

			if (dst_port == 53)
			{
				// 保存本地地址，用于回复时写入.
				auto dns_id = *(uint16_t*)(data + 28);
				m_dnsmap[dns_id] = src_endp;

				if (!m_dns_server.empty()) // 替换dns为指定的dns服务器.
				{
					boost::system::error_code ec;
					auto dns_addr = boost::asio::ip::address_v4::from_string(m_dns_server, ec);
					if (!ec)
					{
						dst_endp.address(dns_addr);
					}
				}
			}

			// 转发数据到socks服务器.
			if (!m_udp_socks_up)
				return true;

			auto result = m_udp_socks->udp_packet(dst_endp, data + 28, udp_len - 8);
			boost::local_shared_ptr<std::string> bufptr = boost::make_local_shared<std::string>(result);
			m_udp_socket.async_send_to(boost::asio::buffer(*bufptr),
				m_udp_socks->udp_endpoint(), [this, bufptr]
				(const boost::system::error_code& error, std::size_t bytes_transferred)
			{
				if (error)
				{
					std::cout << "udp async_send_to error: " << error.message() << std::endl;
					return;
				}

				// nothing to do in here.
			});

			return true;
		}
		case 6:
		{
			// TODO: 暂无实现.
		}
		}

		return false;
	}


private:
	boost::asio::io_context& m_io_context;
	boost::asio::io_context::strand m_strand;
	boost::asio::steady_timer m_timer;
	buffer_queue m_buffer_queue;
	boost::asio::streambuf m_buffer;
	tuntap& m_dev;
	struct netif m_netif;
	std::string m_dns_server;
	boost::local_shared_ptr<socks::socks_client> m_udp_socks;
	tcp::socket m_socket_socks;
	udp::socket m_udp_socket;
	bool m_udp_socks_up;
	struct udp_portmap
	{
		std::time_t tick;
		udp::endpoint local_endp;
	};
	std::map<uint64_t, udp_portmap> m_portmap;
	std::map<uint16_t, udp::endpoint> m_dnsmap;
	// 数据接收缓冲.
	struct recv_buffer
	{
		udp::endpoint endp;
		boost::array<char, 2048> buffer;
	};
	enum { MAX_RECV_BUFFER_SIZE = 712 };
	std::map<int, recv_buffer> m_recv_buffers;
	std::string m_socks_server;
	std::atomic_int m_num_clients;
};


int main(int argc, char** argv)
{
	platform_init();

	io_context io;

	dev_config cfg = { "10.0.0.1", "255.255.255.0", "10.0.0.0" };
	// dev_config cfg = { "0.0.0.0", "255.255.255.255", "0.0.0.0" };

	cfg.dev_name_ = "VPN01";
	if (argc >= 2)
		cfg.dev_name_ = argv[1];

	tuntap tap(io);
	auto dev_list = tap.take_device_list();
	std::string guid;
	for (auto& i : dev_list)
	{
		if (i.name_ == cfg.dev_name_)
		{
			cfg.guid_ = i.guid_;
			break;
		}
	}

	streambuf read_buf;

	cfg.dev_type_ = tuntap_service::dev_tun;
	// cfg.tun_fd_ = _fileno(stdin);
	if (!tap.open(cfg))
	{
		return -1;
	}

	// 创建tun2socks对象.
	tun2socks ts(io, tap);

	// 启动tun2socks.
	ts.start("10.0.0.2", cfg.mask_, argv[2]);

	// running...
	io.run();

	return 0;
}
