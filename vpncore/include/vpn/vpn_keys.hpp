#pragma once

#include <fstream>
#include <string>
#include <vector>

#include "crypto/xchacha20poly1305_crypto.hpp"

namespace avpncore {
	using vpn_keys = std::vector<crypto::xchacha20poly1305_key>;

	inline vpn_keys load_vpn_keys(const std::string& file)
	{
		vpn_keys keys;
		std::ifstream ifs(file, std::ifstream::in);
		std::string line;

		while (ifs.good())
		{
			std::getline(ifs, line);
			if (line.empty())
				continue;
			keys.push_back(line);
		}

		return keys;
	}
}
