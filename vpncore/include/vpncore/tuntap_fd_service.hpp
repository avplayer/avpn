#pragma once
#include "boost/asio.hpp"
#include "boost/thread.hpp"
#include "boost/bind.hpp"
#include "boost/smart_ptr/scoped_ptr.hpp"
#include "boost/smart_ptr/local_shared_ptr.hpp"
#include "boost/smart_ptr/make_local_shared.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <memory>

#ifdef AVPN_LINUX

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>

#endif

#ifdef AVPN_LINUX
extern "C" {
#include <linux/if_tun.h>

#include <asm/types.h>
#include <libnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
}

// #define ARPHRD_NONE			0xFFFE
// #define ARPHRD_ETHER        1

#ifndef IFF_TUN
#define IFF_TUN             0x0001
#endif // !IFF_TUN

#ifndef IFF_TAP
#define IFF_TAP             0x0002
#endif // !IFF_TAP

#ifndef IFF_NO_PI
#define IFF_NO_PI			0x1000
#endif // !IFF_NO_PI

static const char			drv_name[] = "tun";
#define TUNDEV				"/dev/net/tun"

#endif

#ifdef AVPN_FREEBSD

#include <net/if_tun.h>
#include <net/if_tap.h>

#endif

#include "tuntap_config.hpp"

namespace tuntap_service {

	template <typename ReturnType>
	inline ReturnType error_wrapper(ReturnType return_value,
		boost::system::error_code& ec)
	{
		ec = boost::system::error_code(errno,
			boost::asio::error::get_system_category());
		return return_value;
	}

	namespace details {

		inline int read_tuntap_prop(const char *dev, const char *prop, long *value)
		{
			char fname[128], buf[80], *endp, *nl;
			FILE *fp;
			long result;
			int ret;

			ret = snprintf(fname, sizeof(fname), "/sys/class/net/%s/%s",
				dev, prop);

			if (ret <= 0 || ret >= sizeof(fname)) {
				fprintf(stderr, "could not build pathname for property\n");
				return -1;
			}

			fp = fopen(fname, "r");
			if (fp == NULL) {
				fprintf(stderr, "fopen %s: fail\n", fname);
				return -1;
			}

			if (!fgets(buf, sizeof(buf), fp)) {
				fprintf(stderr, "property \"%s\" in file %s is currently unknown\n", prop, fname);
				fclose(fp);
				goto out;
			}

			nl = strchr(buf, '\n');
			if (nl)
				*nl = '\0';

			fclose(fp);
			result = strtol(buf, &endp, 0);

			if (*endp || buf == endp) {
				fprintf(stderr, "value \"%s\" in file %s is not a number\n",
					buf, fname);
				goto out;
			}

			*value = result;
			return 0;

		out:
			fprintf(stderr, "Failed to parse %s\n", fname);
			return -1;
		}
	}

	class tuntap_fd_service
		: public boost::asio::io_context::service
	{
		// c++11 noncopyable.
		tuntap_fd_service(const tuntap_fd_service&) = delete;
		tuntap_fd_service& operator=(const tuntap_fd_service&) = delete;

	public:
		static boost::asio::io_context::id id;
		typedef tuntap_fd_service* impl_type;

		explicit tuntap_fd_service(boost::asio::io_context& io_context)
			: boost::asio::io_context::service(io_context)
			, m_work_context()
			, m_work_strand(m_work_context)
			, m_work(boost::asio::make_work_guard(m_work_context))
			, m_work_thread(new boost::thread(
				boost::bind(&boost::asio::io_context::run, &m_work_context)))
			, m_tuntap_fd(0)
		{
			// 程序开始时获取tuntap列表.
			fetch_tuntap();
		}

		~tuntap_fd_service()
		{
			m_work.reset();
			if (m_work_thread)
				m_work_thread->join();

		}

		void shutdown_service()
		{
		}

		impl_type null() const
		{
			return nullptr;
		}

		void create(impl_type& impl)
		{
			impl = this;
		}

		void destroy(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			close(impl);
			// delete impl;
			impl = null();
		}


		bool open(impl_type& impl, const dev_config& cfg)
		{
			m_tuntap_fd = cfg.tun_fd_;
#ifdef AVPN_LINUX
			struct ifreq ifr;
			int fd;

			if (!cfg.tun_fd_)
			{
				fd = ::open(TUNDEV, O_RDWR);
				if (cfg.tun_fd_ < 0)
					return false;
			}

			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_flags = IFF_NO_PI;
			if (cfg.dev_type_ == dev_tun)
				ifr.ifr_flags |= IFF_TUN;
			else if (cfg.dev_type_ == dev_tap)
				ifr.ifr_flags |= IFF_TAP;
			else
				return false;

			if (!cfg.dev_name_.empty() && cfg.dev_name_.size() < IFNAMSIZ)
				strncpy(ifr.ifr_name, cfg.dev_name_.data(), IFNAMSIZ);

			if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) //打开虚拟网卡
			{
				::close(fd);
				return false;
			}

			printf("TUN / TAP device %s opened", ifr.ifr_name);
			// cfg.dev_name_ = ifr.ifr_name;

			// open dummy socket for ioctls
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			if (sock < 0)
			{
				::close(fd);
				return false;
			}

			if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}

			if (cfg.dev_type_ == dev_tun)
				m_frame_mtu = ifr.ifr_mtu;
			else
				m_frame_mtu = ifr.ifr_mtu + 14; // ethernet header=dest(6)+src(6)+type(2)=14

			if (ioctl(sock, SIOCGIFHWADDR, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}
			::close(sock);

			// 复制mac地址.
			m_mac_addr.resize(6);
			if (ifr.ifr_hwaddr.sa_data)
			{
				memcpy(m_mac_addr.data(), ifr.ifr_hwaddr.sa_data, 6);
			}

			// 设置fd为非阻塞.
			if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
			{
				::close(fd);
				return false;
			}

			m_tuntap_fd = fd;
#endif
			return true;
		}

		void close(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
#ifdef AVPN_LINUX
			if (m_tuntap_fd != 0)
			{
				::close(m_tuntap_fd);
				m_tuntap_fd = 0;
			}
#endif
		}

		class avpn_async_operation {
		public:
			virtual void do_work() = 0;
			tuntap_fd_service* self_;
			int fd_;
		};

		void start_async_op(avpn_async_operation *op)
		{
			op->do_work();
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		class async_read_op : public avpn_async_operation
		{
		public:
			async_read_op(const MutableBufferSequence& buffers, ReadHandler& handler)
				: buffers_(buffers)
				, handler_(BOOST_ASIO_MOVE_CAST(ReadHandler)(handler))
			{}

			virtual void do_work()
			{
				std::size_t bytes_transferred = 0;
				boost::system::error_code ec;

				auto nbytes = buffers_.size();
				auto buf = boost::asio::buffer_cast<void*>(buffers_);

				// Read some data.
				for (;;)
				{
					// Try to complete the operation without blocking.
					errno = 0;
					bytes_transferred = error_wrapper(::read(
						fd_, buf, static_cast<unsigned int>(nbytes)), ec);

					// Check if operation succeeded.
					if (bytes_transferred > 0)
						break;

					// Check for EOF.
					if (bytes_transferred == 0)
					{
						ec = boost::asio::error::eof;
						break;
					}

					// Operation failed.
					if ((ec != boost::asio::error::would_block
							&& ec != boost::asio::error::try_again))
						break;
				}

				self_->get_io_context().dispatch(boost::bind(
					&async_read_op<MutableBufferSequence, ReadHandler>::do_complete,
						this, ec, bytes_transferred));
			}

			void do_complete(const boost::system::error_code& ec,
											std::size_t bytes_transferred)
			{
				handler_(ec, bytes_transferred);
				delete this;
			}

			MutableBufferSequence buffers_;
			ReadHandler handler_;
		};

		template <typename MutableBufferSequence, typename ReadHandler>
		void start_async_read(const MutableBufferSequence& buffers, ReadHandler& handler)
		{
			typedef async_read_op<MutableBufferSequence, ReadHandler> op;
			avpn_async_operation *p = new op(buffers, handler);
			p->self_ = this;
			p->fd_ = m_tuntap_fd;
			m_work_context.post(
				boost::bind(&tuntap_fd_service::start_async_op, this, p));
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(impl_type& impl, const MutableBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
		{
			BOOST_ASSERT("impl == this" && impl == this);

			boost::asio::async_completion<ReadHandler,
				void(boost::system::error_code, std::size_t)> init(handler);

			start_async_read(buffers, init.completion_handler);

			return init.result.get();
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		class async_write_op : public avpn_async_operation
		{
		public:
			async_write_op(const ConstBufferSequence& buffers, WriteHandler& handler)
				: buffers_(buffers)
				, handler_(BOOST_ASIO_MOVE_CAST(WriteHandler)(handler))
			{}

			virtual void do_work()
			{
				std::size_t bytes_transferred = 0;
				boost::system::error_code ec;

				auto nbytes = buffers_.size();
				auto buf = boost::asio::buffer_cast<const void*>(buffers_);

				// Read some data.
				for (;;)
				{
					// Try to complete the operation without blocking.
					errno = 0;
					bytes_transferred = error_wrapper(::write(fd_,
						buf, static_cast<unsigned int>(nbytes)), ec);

					// Check if operation succeeded.
					if (bytes_transferred > 0)
						break;

					// Check for EOF.
					if (bytes_transferred == 0)
					{
						ec = boost::asio::error::eof;
						break;
					}

					// Operation failed.
					if ((ec != boost::asio::error::would_block
						&& ec != boost::asio::error::try_again))
						break;
				}

				self_->get_io_context().dispatch(boost::bind(
					&async_write_op<ConstBufferSequence, WriteHandler>::do_complete,
						this, ec, bytes_transferred));
			}

			void do_complete(const boost::system::error_code& ec,
				std::size_t bytes_transferred)
			{
				handler_(ec, bytes_transferred);
				delete this;
			}

			ConstBufferSequence buffers_;
			WriteHandler handler_;
		};

		template <typename ConstBufferSequence, typename WriteHandler>
		void start_async_write(const ConstBufferSequence& buffers, WriteHandler& handler)
		{
			typedef async_write_op<ConstBufferSequence, WriteHandler> op;
			avpn_async_operation *p = new op(buffers, handler);
			p->self_ = this;
			p->fd_ = m_tuntap_fd;
			m_work_context.post(
				boost::bind(&tuntap_fd_service::start_async_op, this, p));
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(impl_type& impl, const ConstBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			boost::asio::async_completion<WriteHandler,
				void(boost::system::error_code, std::size_t)> init(handler);

			start_async_write(buffers, init.completion_handler);

			return init.result.get();
		}

		std::vector<device_tuntap> take_device_list(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_device_list;
		}

		bool take_mac(impl_type& impl, char mac[6])
		{
			BOOST_ASSERT("impl == this" && impl == this);
			if (m_tuntap_fd == 0)
				return false;
			std::memcpy(mac, m_mac_addr.data(), 6);
			return true;
		}

		// 获取当前打开的tuntap设备的mtu.
		int take_mtu(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_frame_mtu;
		}

	private:
		void fetch_tuntap()
		{
#ifdef AVPN_LINUX
			struct rtnl_handle rth;
			if (rtnl_open(&rth, 0) != 0)
				return;
			if (rtnl_wilddump_request(&rth, AF_UNSPEC, RTM_GETLINK) < 0)
				return;
			if (rtnl_dump_filter(&rth, list_tuntap_func, (void*)this) < 0)
				return;
			rtnl_close(&rth);
#endif
		}

#ifdef AVPN_LINUX
		// friend 
		static int list_tuntap_func(const struct sockaddr_nl *who,
			struct nlmsghdr *n, void *arg)
		{
			auto pthis = (tuntap_fd_service*)arg;
			return pthis->list_tuntap(who, n);
		}
#endif

		int list_tuntap(const struct sockaddr_nl *who,
			struct nlmsghdr *n)
		{
#ifdef AVPN_LINUX
			struct ifinfomsg *ifi = (struct ifinfomsg*)NLMSG_DATA(n);
			struct rtattr *tb[IFLA_MAX + 1];
			struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
			const char *name, *kind;
			long flags, owner = -1, group = -1;

			if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
				return 0;
			if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
				return -1;

			switch (ifi->ifi_type) {
			case ARPHRD_NONE:
			case ARPHRD_ETHER:
				break;
			default:
				return 0;
			}

			parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));

			if (!tb[IFLA_IFNAME])
				return 0;
			if (!tb[IFLA_LINKINFO])
				return 0;

			parse_rtattr(linkinfo, IFLA_INFO_MAX, (struct rtattr *)RTA_DATA(tb[IFLA_LINKINFO]), RTA_PAYLOAD(tb[IFLA_LINKINFO]));
			// parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, (void*)tb[IFLA_LINKINFO]);
			if (!linkinfo[IFLA_INFO_KIND])
				return 0;

			kind = rta_getattr_str(linkinfo[IFLA_INFO_KIND]);
			if (strcmp(kind, drv_name))
				return 0;

			name = rta_getattr_str(tb[IFLA_IFNAME]);
			if (details::read_tuntap_prop(name, "tun_flags", &flags))
				return 0;

			if (flags & IFF_TUN)
			{
				device_tuntap dev;
				dev.name_ = name;
				dev.dev_type_ = dev_tun;
				m_device_list.push_back(dev);
				printf("iframe: %s, tun type: %d\n", name, flags);
			}

			if (flags & IFF_TAP)
			{
				device_tuntap dev;
				dev.name_ = name;
				dev.dev_type_ = dev_tap;
				m_device_list.push_back(dev);
				printf("iframe: %s, tap type: %d\n", name, flags);
			}
#endif
			return 0;
		}

	private:
		boost::asio::io_context m_work_context; // 用于模拟事件机制.
		boost::asio::io_context::strand m_work_strand;
		boost::asio::executor_work_guard<
			boost::asio::io_context::executor_type> m_work;
		boost::scoped_ptr<boost::thread> m_work_thread;
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;
		int m_frame_mtu;
		std::vector<uint8_t> m_mac_addr;
		int m_tuntap_fd;
	};

}
