#pragma once
#include <string>
#include <vector>
#include <memory>

#include "boost/asio.hpp"

#if BOOST_ASIO_WINDOWS
#include "tuntap_windows_service.hpp"
#endif


#include "basic_tuntap.hpp"

namespace tuntap_service {

	// 定义tuntap实现.
#if BOOST_ASIO_WINDOWS
	typedef basic_tuntap<tuntap_windows_service> tuntap;
#else
	typedef basic_tuntap<tuntap_fd_serivce> tuntap;
#endif

}
