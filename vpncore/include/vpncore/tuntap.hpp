#pragma once
#include <string>
#include <vector>
#include <memory>

#include "boost/asio.hpp"

#ifdef AVPN_WINDOWS
#include "tuntap_windows_service.hpp"
#else
#include "tuntap_fd_service.hpp"
#endif


#include "basic_tuntap.hpp"

namespace tuntap_service {

	// 定义tuntap实现.
#ifdef AVPN_WINDOWS
	typedef basic_tuntap<tuntap_windows_service> tuntap;
#else
	typedef basic_tuntap<tuntap_fd_service> tuntap;
#endif

}
