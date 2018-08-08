#pragma once
#include <string>

namespace tuntap_service {

	struct device_tuntap
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

}
