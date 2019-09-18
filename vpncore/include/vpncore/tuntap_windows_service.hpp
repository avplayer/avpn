#pragma once
#include "boost/asio.hpp"
#include "boost/smart_ptr/local_shared_ptr.hpp"
#include "boost/smart_ptr/make_local_shared.hpp"

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64) || defined(WIN64)

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif // _WINSOCK_DEPRECATED_NO_WARNINGS

#include <tchar.h>
#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#endif

#include <iostream>
#include <string>
#include <vector>
#include <memory>

#ifndef TUNTAP_IOCTL_DEFINED
#define TUNTAP_IOCTL_DEFINED

#define USERMODEDEVICEDIR				TEXT("\\\\.\\Global\\")
#define TAPSUFFIX						TEXT(".tap")
#define ADAPTER_KEY						TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}")
#define NETWORK_CONNECTIONS_KEY			TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}")

#define TAP_CONTROL_CODE(request, method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE(10, METHOD_BUFFERED)

#endif // !TUNTAP_IOCTL_DEFINED

#include "vpncore/tuntap_config.hpp"
#include "vpncore/logging.hpp"

namespace tuntap_service {

	namespace details {
		inline void utf8_utf16(const std::string& utf8, std::wstring& utf16)
		{
			auto len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
			if (len > 0)
			{
				wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
				MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, tmp, len);
				utf16.assign(tmp);
				free(tmp);
			}
		}

		inline void utf16_utf8(const std::wstring& utf16, std::string& utf8)
		{
			auto len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, 0, 0);
			if (len > 0)
			{
				char* tmp = (char*)malloc(sizeof(char) * len);
				WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, tmp, len, 0, 0);
				utf8.assign(tmp);
				free(tmp);
			}
		}

		inline DWORD get_interface_index(const char *guid)
		{
			ULONG index;
			DWORD status;
			wchar_t wbuf[256] = { 0 };
			_swprintf(wbuf, L"\\DEVICE\\TCPIP_%S", guid);
			if ((status = GetAdapterIndex(wbuf, &index)) != NO_ERROR)
				return (DWORD)~0;
			else
				return index;
		}

		inline int tap_win32_set_status(HANDLE handle, int status)
		{
			unsigned long len = 0;
			return DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
				&status, sizeof(status), &status, sizeof(status), &len, NULL);
		}

		inline std::string error_format(DWORD err)
		{
			// Retrieve the system error message for the last-error code
			LPVOID lpMsgBuf;

			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpMsgBuf,
				0, NULL);

			// Display the error message and exit the process.
			std::string error_msg;
#ifdef UNICODE
			std::wstring tmp((LPTSTR)lpMsgBuf);
			utf16_utf8(tmp, error_msg);
#else
			error_msg.assign((char*)lpMsgBuf);
#endif // UNICODE

			LocalFree(lpMsgBuf);

			return error_msg;
		}
	}

	class tuntap_windows_service
		: public boost::asio::detail::service_base<tuntap_windows_service>
	{
		// c++11 noncopyable.
		tuntap_windows_service(const tuntap_windows_service&) = delete;
		tuntap_windows_service& operator=(const tuntap_windows_service&) = delete;

	public:
		typedef tuntap_windows_service* impl_type;

		explicit tuntap_windows_service(boost::asio::io_context& io_context)
			: boost::asio::detail::service_base<tuntap_windows_service>(io_context)
			, m_io_handle(io_context)
			, m_handle(INVALID_HANDLE_VALUE)
		{
			std::map<std::string, std::string> dev_map;
			HKEY adapter_key;
			typedef std::unique_ptr<std::remove_pointer<HKEY>::type,
				decltype(&RegCloseKey)> register_closer;

			auto status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				ADAPTER_KEY, 0, KEY_READ, &adapter_key);
			if (status != ERROR_SUCCESS)
				return;

			register_closer adapter_key_close(adapter_key, &RegCloseKey);

			for (int i = 0; ; i++)
			{
				TCHAR enum_name[256] = { 0 };
				TCHAR unit_string[256] = { 0 };
				DWORD len = 256;
				status = RegEnumKeyEx(adapter_key,
					i, enum_name, &len, NULL, NULL, NULL, NULL);
				if (status == ERROR_NO_MORE_ITEMS)
					break;
				else if (status != ERROR_SUCCESS)
					break;
				else
				{
					_stprintf(unit_string, TEXT("%s\\%s"), ADAPTER_KEY, enum_name);

					HKEY unit_key;
					status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						unit_string, 0, KEY_READ, &unit_key);
					if (status != ERROR_SUCCESS)
						break;
					register_closer unit_key_close(unit_key, &RegCloseKey);

					TCHAR component_id_string[] = TEXT("ComponentId");
					TCHAR net_cfg_instance_id_string[] = TEXT("NetCfgInstanceId");
					DWORD data_type;
					TCHAR component_id[256];
					len = 256;
					status = RegQueryValueEx(
						unit_key,
						component_id_string,
						NULL,
						&data_type,
						(LPBYTE)component_id,
						&len);
					if (status != ERROR_SUCCESS)
						break;

					if (!_tcscmp(component_id, TEXT("tap0901")))
					{
						TCHAR net_cfg_instance_id[256];
						len = 256;
						status = RegQueryValueEx(
							unit_key,
							net_cfg_instance_id_string,
							NULL,
							&data_type,
							(LPBYTE)net_cfg_instance_id,
							&len);
						if (status != ERROR_SUCCESS)
							break;

						std::string tmp;
#ifdef UNICODE
						utf16_utf8(net_cfg_instance_id, tmp);
#else
						tmp = net_cfg_instance_id;
#endif
						dev_map.insert(std::make_pair(tmp, ""));

						LOG_DBG << "component_id " << component_id
							<< ", net_cfg_instance_id " << tmp;
					}
				}
			}

			HKEY network_connections_key;
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &network_connections_key);
			if (status != ERROR_SUCCESS)
				return;

			register_closer network_connections_key_close(network_connections_key, &RegCloseKey);

			for (int i = 0; ; i++)
			{
				TCHAR enum_name[256];
				DWORD len = 256;
				status = RegEnumKeyEx(network_connections_key,
					i, enum_name, &len, NULL, NULL, NULL, NULL);
				if (status == ERROR_NO_MORE_ITEMS)
					break;
				else if (status != ERROR_SUCCESS)
					break;
				else
				{
					HKEY connection_key;
					TCHAR connection_string[256];

					_stprintf(connection_string,
						TEXT("%s\\%s\\Connection"), NETWORK_CONNECTIONS_KEY, enum_name);

					status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						connection_string, 0, KEY_READ, &connection_key);
					if (status != ERROR_SUCCESS)
						continue;
					register_closer connection_key_close(connection_key, &RegCloseKey);

					TCHAR name_data[256];
					TCHAR name_string[] = TEXT("Name");
					len = 256;

					DWORD name_type;
					status = RegQueryValueEx(connection_key, name_string,
						NULL, &name_type, (LPBYTE)name_data, &len);
					if (status != ERROR_SUCCESS)
						continue;

					std::string dev_name;
					{
#ifdef UNICODE
						utf16_utf8(name_data, dev_name);
#else
						dev_name = name_data;
#endif
					}

					std::string guid_key;
					{
#ifdef UNICODE
						utf16_utf8(enum_name, guid_key);
#else
						guid_key = enum_name;
#endif
					}

					auto iter = dev_map.find(guid_key);
					if (iter != dev_map.end())
					{
						iter->second.assign(dev_name);
						LOG_DBG << "Tuntap device name " << dev_name;
					}
				}
			}

			for (auto& item : dev_map)
			{
				m_device_list.push_back(device_tuntap{ item.second, item.first });
			}
		}

		~tuntap_windows_service()
		{}

		void shutdown_service()
		{
		}

		impl_type null() const
		{
			return nullptr;
		}

		void create(impl_type& impl)
		{
			impl = this;
		}

		void destroy(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			close(impl);
			// delete impl;
			impl = null();
		}

		bool open(impl_type& impl, const dev_config& cfg)
		{
			BOOST_ASSERT("impl == this" && impl == this);

			if_index = details::get_interface_index(cfg.guid_.c_str());

			TCHAR device_path[256] = { 0 };
			_stprintf(device_path, TEXT("%s%s%s"),
				USERMODEDEVICEDIR, cfg.guid_.c_str(), TAPSUFFIX);
			LOG_DBG << device_path;
			auto handle = CreateFile((LPCTSTR)device_path, GENERIC_READ | GENERIC_WRITE,
				0, 0, OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

			if (handle == INVALID_HANDLE_VALUE)
			{
				return FALSE;
			}
			// TAP-Win32 Driver Version.
			struct {
				unsigned long major;
				unsigned long minor;
				unsigned long debug;
			} version;

			DWORD len;

			if (!DeviceIoControl(handle, TAP_IOCTL_GET_VERSION,
				&version, sizeof(version),
				&version, sizeof(version), &len, NULL))
			{
				CloseHandle(handle);
				return false;
			}

			// usage of numeric constants is ugly, but this is really tied to this version of the driver
			if (cfg.dev_type_ == tuntap_service::dev_tun
				&& version.major == 9 && version.minor < 8)
			{
				LOG_DBG << "WARNING:  Tap-Win32 driver version " << (int)version.major << "." << (int)version.minor
					<< " does not support IPv6 in TUN mode. IPv6 will not work. Upgrade your Tap-Win32 driver.";
			}

			// tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy
			if (cfg.dev_type_ == tuntap_service::dev_tun
				&& version.major == 9 && version.minor == 8)
			{
				LOG_DBG << "ERROR:  Tap-Win32 driver version " << (int)version.major << "." << (int)version.minor
					<< " is buggy regarding small IPv4 packets in TUN mode. Upgrade your Tap-Win32 driver.";
			}

			if (cfg.dev_type_ == tuntap_service::dev_tun)
			{
				uint32_t tun_addrs[3];

				inet_pton(AF_INET, cfg.local_.c_str(), &tun_addrs[0]);	// local ip
				inet_pton(AF_INET, cfg.mask_.c_str(), &tun_addrs[1]);	// local ip & mask
				inet_pton(AF_INET, cfg.mask_.c_str(), &tun_addrs[2]);	// mask
				tun_addrs[1] = tun_addrs[2] & tun_addrs[0];

				if (!DeviceIoControl(handle, TAP_IOCTL_CONFIG_TUN,
					tun_addrs, sizeof(tun_addrs), tun_addrs, sizeof(tun_addrs), &len, NULL))
				{
					CloseHandle(handle);
					return false;
				}

				// if (cfg.ifconfig_setup_)
				{
					auto ep1 = boost::asio::ip::address_v4(ntohl(tun_addrs[1]));
					auto ep0 = boost::asio::ip::address_v4(ntohl(tun_addrs[0]));
					auto ep2 = boost::asio::ip::address_v4(ntohl(tun_addrs[2]));
					LOG_DBG << "Set TAP-Windows TUN subnet mode network/local/netmask = " <<
						ep1.to_string() << "/" << ep0.to_string() << "/" << ep2.to_string();
				}
			}
			else
			{
// 				netsh_ifconfig(
// 					cfg.local_,
// 					cfg.mask_,
// 					cfg.dev_name_);
			}

			// get mtu.
			ULONG mtu;
			if (DeviceIoControl(handle, TAP_IOCTL_GET_MTU,
				&mtu, sizeof(mtu),
				&mtu, sizeof(mtu), &len, NULL))
			{
				LOG_DBG << "TAP-Windows MTU=" << (int)mtu;
			}

			uint8_t mac[6];

			if (!DeviceIoControl(handle, TAP_IOCTL_GET_MAC, mac, 6, mac, 6, &len, 0))
			{
				CloseHandle(handle);
				return false;
			}
			char buf[13] = { 0 };
			sprintf(buf, "%02X%02X%02X%02X%02X%02X",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


			uint32_t ep[4];

			ep[0] = inet_addr(cfg.local_.c_str());	// local ip
			ep[1] = inet_addr(cfg.mask_.c_str());	// mask
			ep[2] = htonl(htonl(ep[0] | ~ep[1]) - 1);

			inet_pton(AF_INET, cfg.local_.c_str(), &ep[0]);	// local ip
			inet_pton(AF_INET, cfg.mask_.c_str(), &ep[1]);	// mask
			inet_pton(AF_INET, cfg.dhcp_.c_str(), &ep[2]);

			ep[3] = 0xFFFFFFFE;

			if (!DeviceIoControl(handle, TAP_IOCTL_CONFIG_DHCP_MASQ,
				ep, sizeof(ep), ep, sizeof(ep), &len, NULL))
			{
				CloseHandle(handle);
				return false;
			}


			if (!details::tap_win32_set_status(handle, TRUE))
			{
				CloseHandle(handle);
				return false;
			}

			// 	DWORD ret = FlushIpNetTable(index);
			// 	if (ret != NO_ERROR)
			// 	{
			// 		std::string msg;
			// 		msg = error_format(ret);
			// 		std::cout << "FlushIpNetTable: " << msg << std::endl;
			// 	}

			if (m_handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_handle);
			}

			m_config = cfg;
			m_handle = handle;
			m_frame_mtu = (int)mtu;
			m_mac_addr.resize(6);
			std::memcpy(m_mac_addr.data(), mac, 6);

			boost::system::error_code ec;
			m_io_handle.assign(handle, ec);
			if (ec)
			{
				LOG_DBG << "Assign to random_access_handle: " << ec.message();
			}

			return true;
		}

		void close(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);

			if (m_io_handle.is_open())
			{
				details::tap_win32_set_status(m_handle, FALSE);

				boost::system::error_code ignore_ec;
				m_io_handle.close(ignore_ec);
			}
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(impl_type& impl, const MutableBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_io_handle.async_read_some_at(0, buffers, handler);
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(impl_type& impl, const ConstBufferSequence& buffers,
				BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_io_handle.async_write_some_at(0, buffers, handler);
		}

		std::vector<device_tuntap> take_device_list(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_device_list;
		}

		bool take_mac(impl_type& impl, char mac[6])
		{
			BOOST_ASSERT("impl == this" && impl == this);
			if (m_handle == INVALID_HANDLE_VALUE)
				return false;
			std::memcpy(mac, m_mac_addr.data(), 6);
			return true;
		}

		// 获取当前打开的tuntap设备的mtu.
		int take_mtu(impl_type& impl)
		{
			BOOST_ASSERT("impl == this" && impl == this);
			return m_frame_mtu;
		}

		int get_if_index() const
		{
			return if_index;
		}
	private:
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;
		HANDLE m_handle;
		int m_frame_mtu;
		std::vector<uint8_t> m_mac_addr;
		boost::asio::windows::random_access_handle m_io_handle;
		int if_index;
	};
}
