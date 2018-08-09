#ifdef AVPN_WINDOWS
#include "tuntap_windows_service.hpp"
#endif

#ifdef AVPN_LINUX
#include "tuntap_fd_service.hpp"
#endif

namespace tuntap_service {

#ifdef AVPN_WINDOWS
	boost::asio::io_context::id tuntap_windows_service::id;
#endif // AVPN_WIN

#ifdef AVPN_LINUX
	boost::asio::io_context::id tuntap_fd_service::id;
#endif
} // namespace tuntap_service

