#pragma once
#include <string>
#include <vector>
#include <memory>

#include "boost/asio.hpp"
#include "tuntap_config.hpp"

namespace tuntap_service {

	template <typename Service>
	class basic_tuntap
	{
		// c++11 noncopyable.
		basic_tuntap(const basic_tuntap&) = delete;
		basic_tuntap& operator=(const basic_tuntap&) = delete;

	public:
		typedef Service service_type;
		typedef typename service_type::impl_type impl_type;

		explicit basic_tuntap(boost::asio::io_context& io_context)
			: service_(boost::asio::use_service<Service>(io_context)),
			impl_(service_.null())
		{
			service_.create(impl_);
		}

		~basic_tuntap()
		{
			service_.destroy(impl_);
		}

		boost::asio::io_context& get_io_context()
		{
			return service_.get_io_context();
		}

		// 打开指定的tuntap设备，并按cfg配置.
		bool open(const dev_config& cfg)
		{
			return service_.open(impl_, cfg);
		}

		// 关闭已经打开的tuntap设备.
		void close()
		{
			service_.close(impl_);
		}

		// 提供异步读取tuntap设备上的数据到buffer.
		// 函数签名同asio的socket.async_read_some
		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(const MutableBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
		{
			return service_.async_read_some(impl_, buffers, handler);
		}

		// 提供异步写入tuntap设备上的数据到buffer.
		// 函数签名同asio的socket.async_write_some
		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(const ConstBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
		{
			return service_.async_write_some(impl_, buffers, handler);
		}

		// 获取所有tuntap设备列表, 一般在打开tuntap devicep之前
		// 先获取到tuntap, 根据这个列表选择打开指定device.
		std::vector<device_tuntap> take_device_list()
		{
			return service_.take_device_list(impl_);
		}

		// 获取当前打开的tuntap设备的mac.
		bool take_mac(char mac[6])
		{
			return service_.take_mac(impl_, mac);
		}

		// 获取当前打开的tuntap设备的mtu.
		int take_mtu()
		{
			return service_.take_mtu(impl_);
		}

	private:
		service_type & service_;
		impl_type impl_;
	};

}
