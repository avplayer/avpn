#pragma once

#if defined(AVPN_WINDOWS)
#include "vpncore/tuntap_windows_service.hpp"
#elif defined(AVPN_LINUX)
#include "vpncore/tuntap_fd_service.hpp"
#else
#error unsupported platform
#endif



#include "vpncore/basic_tuntap.hpp"

namespace tuntap_service {

	// 定义不同平台的tuntap实现.
#if defined(AVPN_WINDOWS)
	typedef basic_tuntap<tuntap_windows_service> tuntap;
#elif defined(AVPN_LINUX)
	typedef basic_tuntap<tuntap_fd_service> tuntap;
#endif

}
