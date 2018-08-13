#pragma once

#include <boost/asio/ip/tcp.hpp>

namespace avpncore {

	// 定义一个源地址和目标地址的结构.
	struct endpoint_pair
	{
		boost::asio::ip::tcp::endpoint src_;
		boost::asio::ip::tcp::endpoint dst_;

		int type_;

		endpoint_pair()
			: type_(-1)
		{}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(uint32_t src_ip, uint16_t src_port,
			uint32_t dst_ip, uint16_t dst_port)
			: type_(-1)
		{
			src_.address(boost::asio::ip::address_v4(ntohl(src_ip)));
			src_.port(ntohs(src_port));
			dst_.address(boost::asio::ip::address_v4(ntohl(dst_ip)));
			dst_.port(ntohs(dst_port));
		}

		bool empty() const
		{
			return type_ < 0;
		}

		void reserve()
		{
			auto tmp = src_;
			src_ = dst_;
			dst_ = tmp;
		}

		std::string to_string()
		{
			std::ostringstream oss;
			oss << src_ << " - " << dst_;
			return oss.str();
		}
	};

	bool operator==(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ == rh.src_ && lh.dst_ == rh.dst_)
			return true;
		return false;
	}

	bool operator!=(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ != rh.src_ || lh.dst_ != rh.dst_)
			return true;
		return false;
	}

	bool operator<(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ < rh.src_)
			return true;

		if (lh.src_ != rh.src_)
			return false;

		if (lh.dst_ < rh.dst_)
			return true;

		return false;
	}

	bool operator>(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (rh < lh)
			return true;
		if (lh == rh)
			return false;
		return true;
	}
}

namespace std
{
	template<> struct hash<boost::asio::ip::tcp::endpoint>
	{
		typedef boost::asio::ip::tcp::endpoint argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& s) const
		{
			std::string temp = s.address().to_string();
			std::size_t seed = 0;
			boost::hash_combine(seed, temp);
			boost::hash_combine(seed, s.port());
			return seed;
		}
	};

	template<> struct hash<avpncore::endpoint_pair>
	{
		typedef avpncore::endpoint_pair argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& s) const
		{
			result_type const h1(std::hash<boost::asio::ip::tcp::endpoint>{}(s.src_));
			result_type const h2(std::hash<boost::asio::ip::tcp::endpoint>{}(s.dst_));
			std::size_t seed = 0;
			boost::hash_combine(seed, h1);
			boost::hash_combine(seed, h2);
			return seed;
		}
	};
}
