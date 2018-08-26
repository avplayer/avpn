#pragma once

#include <unordered_map>

#include "vpncore/tuntap.hpp"
#include "vpncore/endpoint_pair.hpp"

#include "vpn/vpn_ws_session.hpp"

namespace avpncore {
	using namespace tuntap_service;
	using boost::asio::ip::tcp;

	class vpn_demuxer
	{
		// c++11 noncopyable.
		vpn_demuxer(const vpn_demuxer&) = delete;
		vpn_demuxer& operator=(const vpn_demuxer&) = delete;

	public:
		vpn_demuxer(tuntap& dev)
			: m_device(dev)
		{}
		~vpn_demuxer()
		{}

	public:
		void start()
		{
			ip_demux();
		}

		void start_session(tcp::socket socket)
		{
			auto session = std::make_shared<vpn_ws_session>(std::move(socket));

			// set handlers.
			session->set_register_handler(
				std::bind(&vpn_demuxer::register_vpn_session, this,
					std::placeholders::_1, std::placeholders::_2));
			session->set_remove_handler(
				std::bind(&vpn_demuxer::remove_vpn_session, this,
					std::placeholders::_1));
			session->set_write_ip_handler(
				std::bind(&vpn_demuxer::write2tun, this,
					std::placeholders::_1));
			session->start();
		}

	public:
		void register_vpn_session(const endpoint_pair& endp, vpn_ws_session_ptr& session)
		{
			m_sessions.insert(std::make_pair(endp, session));
		}

		void remove_vpn_session(const endpoint_pair& endp)
		{
			m_sessions.erase(endp);
		}

		void write2tun(ip_buffer buffer)
		{
// 			const auto& endp = buffer.endp_;
// 			if (buffer.empty())			// 连接已经销毁, 传过来空包.
// 			{
// 				remove_stream(endp);
// 				return;
// 			}
//
// 			static uint16_t index = 0;
//
// 			// 打包ip头.
// 			uint8_t* p = buffer.data();
//
// 			*((uint8_t*)(p + 0)) = 0x45; // version
// 			*((uint8_t*)(p + 1)) = 0x00; // tos
// 			*((uint16_t*)(p + 2)) = htons((uint16_t)buffer.len()); // ip length
// 			*((uint16_t*)(p + 4)) = htons(index++);	// id
// 			*((uint16_t*)(p + 6)) = 0x00;	// flag
// 			*((uint8_t*)(p + 8)) = 0x30; // ttl
// 			*((uint8_t*)(p + 9)) = endp.type_; // protocol
// 			*((uint16_t*)(p + 10)) = 0x00; // checksum
//
// 			*((uint32_t*)(p + 12)) = htonl(endp.src_.address().to_v4().to_ulong()); // source
// 			*((uint32_t*)(p + 16)) = htonl(endp.dst_.address().to_v4().to_ulong()); // dest
//
// 			*((uint16_t*)(p + 10)) = (uint16_t)~(unsigned int)standard_chksum(p, 20);// htons(sum); // ip header checksum
//
// 																					 // 写入tun设备.
// 			bool write_in_progress = !m_queue.empty();
// 			m_queue.push_back(buffer);
//
// 			if (!write_in_progress)
// 			{
// 				boost::asio::spawn(m_io_context, std::bind(
// 					&demultiplexer::write_ip_packet, shared_from_this(), std::placeholders::_1));
// 			}
		}

	private:
		void ip_demux()
		{
			m_device.async_read_some(
				m_tun_read_buffer.prepare(64 * 1024), [this]
				(boost::system::error_code ec, std::size_t bytes_transferred)
			{
				if (ec)
					return;
				m_tun_read_buffer.commit(bytes_transferred);

				auto buf = boost::asio::buffer_cast<const uint8_t*>(m_tun_read_buffer.data());
				auto endp = lookup_endpoint_pair(buf, bytes_transferred);

				auto it = m_sessions.find(endp);
				if (it != m_sessions.end())
				{
					auto& session = it->second;

					// 通过session传回client.
					session;
				}

				m_tun_read_buffer.consume(bytes_transferred);

				ip_demux();
			});
		}

	private:
		tuntap& m_device;
		boost::asio::streambuf m_tun_read_buffer;
		std::unordered_map<endpoint_pair, vpn_ws_session_ptr> m_sessions;
	};

}
