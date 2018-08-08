#include <string>
#include <vector>
#include <memory>

#include "boost/asio.hpp"

struct tap_device
{
	std::string name_;	// utf8 encode.
	std::string guid_;
};

struct dev_config
{
	std::string local_;
	std::string mask_;
	std::string gateway_;
	std::string dhcp_;
	std::string guid_;
	std::string dev_name_;
	std::string tun_fd_; // use for linux tun dev.
	enum dev_type {
		dev_tap,
		dev_tun,
	};
	dev_type dev_type_; // true is tap, false is tun.

	bool ifconfig_setup_;
};

struct tap_context;

class tuntap_window_device
{
	// c++11 noncopyable.
	tuntap_window_device(const tuntap_window_device&) = delete;
	tuntap_window_device& operator=(const tuntap_window_device&) = delete;

public:
	tuntap_window_device(boost::asio::io_context& io);
	~tuntap_window_device();

public:
	bool open(const dev_config& cfg);
	void close();

	template <typename MutableBufferSequence, typename ReadHandler>
	BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
		void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence& buffers,
			BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
	{
		return m_io_handle.async_read_some_at(0, buffers, handler);
	}

	template <typename ConstBufferSequence, typename WriteHandler>
	BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
		void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence& buffers,
			BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
	{
		return m_io_handle.async_write_some_at(0, buffers, handler);
	}

	const std::vector<tap_device>& fetch_tap_device_list();
	bool fetch_mac(char mac[6]);
	int fetch_mtu();

private:
	boost::asio::io_context& m_io_context;
	std::vector<tap_device> m_device_list;
	std::shared_ptr<tap_context> m_tap_context;
	boost::asio::windows::random_access_handle m_io_handle;
};

