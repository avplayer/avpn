#include <iostream>
#include <map>
#include <memory>

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

#include "boost/smart_ptr/local_shared_ptr.hpp"
#include "boost/smart_ptr/make_local_shared.hpp"

#include "tuntap_windows.hpp"

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


static
void utf8_utf16(const std::string& utf8, std::wstring& utf16)
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

static
void utf16_utf8(const std::wstring& utf16, std::string& utf8)
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

static
DWORD get_interface_index(const char *guid)
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

static
int tap_win32_set_status(HANDLE handle, int status)
{
	unsigned long len = 0;
	return DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
		&status, sizeof(status), &status, sizeof(status), &len, NULL);
}

static
std::string error_format(DWORD err)
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

static
int run_command(const std::string& cmd, std::string& result)
{
	char buf[128];
	FILE* pipe = nullptr;

	if ((pipe = _popen(cmd.c_str(), "rt")) == nullptr)
		return EXIT_FAILURE;

	while (fgets(buf, 128, pipe))
		result += buf;

	if (feof(pipe))
		return _pclose(pipe);

	return EXIT_FAILURE;
}

static
void netsh_ifconfig(const std::string& ip, const std::string& netmask, const std::string& flex_name)
{
	char buf[256];
	GetEnvironmentVariable("SystemRoot", buf, sizeof(buf));
	std::string sys_root(buf);
	char command[512];

	// example: netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0
	sprintf(command, "%s%sc interface ip set address %s static %s %s",
		sys_root.c_str(),
		"\\system32\\netsh.exe",
		flex_name.c_str(),
		ip.c_str(),
		netmask.c_str());

	std::string result;
	if (run_command(std::string(command), result) == EXIT_FAILURE)
	{
		std::cout << "ERROR: Run command '"
			<< command << "' error: " << result << std::endl;
	}
}

static
void add_route(const std::string& network, const std::string& mask, const std::string& gateway, int metric, int IF)
{
	char buf[256];
	GetEnvironmentVariable("SystemRoot", buf, sizeof(buf));
	std::string sys_root(buf);
	char command[512];

	// example: route ADD 157.0.0.0 MASK 255.0.0.0  157.55.80.1 METRIC 3 IF 2
	//                 destination^      ^mask      ^gateway     metric^    ^
	// 	                                                           Interface^
	// 如果未给出 IF，它将尝试查找给定网关的最佳接口。
	sprintf(command, "%s%sc ADD %s MASK %s %s",
		sys_root.c_str(),
		"\\system32\\route.exe",
		network.c_str(),
		mask.c_str(),
		gateway.c_str());

	std::string cmd = command;

	if (metric != -1)
	{
		sprintf(command, " METRIC %d", metric);
		cmd = cmd + command;
	}

	if (IF != -1)
	{
		sprintf(command, " IF %d", metric);
		cmd = cmd + command;
	}

	std::string result;
	if (run_command(cmd, result) == EXIT_FAILURE)
	{
		std::cout << "ERROR: Run command '"
			<< cmd << "' error: " << result << std::endl;
	}
}

static
void del_route(const std::string& network, const std::string& mask, const std::string& gateway, int metric, int IF)
{
	char buf[256];
	GetEnvironmentVariable("SystemRoot", buf, sizeof(buf));
	std::string sys_root(buf);
	char command[512];

	// example: route DELETE 157.0.0.0 MASK 255.0.0.0  157.55.80.1
	//                    destination^      ^mask      ^gateway
	sprintf(command, "%s%sc DELETE %s MASK %s %s",
		sys_root.c_str(),
		"\\system32\\route.exe",
		network.c_str(),
		mask.c_str(),
		gateway.c_str());

	std::string result;
	if (run_command(std::string(command), result) == EXIT_FAILURE)
	{
		std::cout << "ERROR: Run command '"
			<< command << "' error: " << result << std::endl;
	}
}

static
boost::local_shared_ptr<MIB_IPFORWARDTABLE> get_windows_routing_table()
{
	ULONG size = 0;
	DWORD status;
	boost::local_shared_ptr<MIB_IPFORWARDTABLE> ret;

	status = GetIpForwardTable(NULL, &size, TRUE);
	if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		ret.reset((PMIB_IPFORWARDTABLE)new uint8_t[size]);
		status = GetIpForwardTable(ret.get(), &size, TRUE);
		if (status != NO_ERROR)
		{
			printf("NOTE: GetIpForwardTable returned error: %s (code=%u)\n",
				error_format(status).c_str(),
				(unsigned int)status);
			ret.reset();
		}
	}
	return ret;
}

static const
MIB_IPFORWARDROW* get_default_gateway_row(const boost::local_shared_ptr<MIB_IPFORWARDTABLE>& routes)
{
	DWORD lowest_metric = MAXDWORD;
	const MIB_IPFORWARDROW *ret = NULL;
	int i;
	int best = -1;

	if (routes)
	{
		for (i = 0; i < routes->dwNumEntries; ++i)
		{
			const MIB_IPFORWARDROW *row = &routes->table[i];
			const auto net = ntohl(row->dwForwardDest);
			const auto mask = ntohl(row->dwForwardMask);
			const DWORD index = row->dwForwardIfIndex;
			const DWORD metric = row->dwForwardMetric1;

			auto net_endp = boost::asio::ip::address_v4(net);
			auto mask_endp = boost::asio::ip::address_v4(mask);

			printf("GDGR: route[%d] %s/%s i=%d m=%d\n",
				i,
				net_endp.to_string().c_str(),
				mask_endp.to_string().c_str(),
				(int)index,
				(int)metric);

			if (!net && !mask && metric < lowest_metric)
			{
				ret = row;
				lowest_metric = metric;
				best = i;
			}
		}
	}

	printf("GDGR: best=%d lm=%u\n", best, (unsigned int)lowest_metric);

	return ret;
}

boost::local_shared_ptr<IP_ADAPTER_INFO> get_adapter_info_list()
{
	ULONG size = 0;
	boost::local_shared_ptr<IP_ADAPTER_INFO> pi;
	DWORD status;

	if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
	{
		printf("GetAdaptersInfo #1 failed (status=%u) : %s\n",
			(unsigned int)status,
			error_format(status).c_str());
	}
	else
	{
		pi.reset((PIP_ADAPTER_INFO)new uint8_t[size]);
		if ((status = GetAdaptersInfo(pi.get(), &size)) != NO_ERROR)
		{
			printf("GetAdaptersInfo #2 failed (status=%u) : %s\n",
				(unsigned int)status,
				error_format(status).c_str());
			pi.reset();
		}
	}

	return pi;
}

struct route_entry
{
	boost::asio::ip::address_v4 net;
	boost::asio::ip::address_v4 mask;
	boost::asio::ip::address_v4 gateway;
	boost::asio::ip::address_v4 ifip;
	int metric;
};

route_entry get_default_gateway()
{
	route_entry entry;
	auto adapters = get_adapter_info_list();
	auto routes = get_windows_routing_table();
	const MIB_IPFORWARDROW *row = get_default_gateway_row(routes);

	entry.gateway = boost::asio::ip::address_v4(ntohl(row->dwForwardNextHop));
	entry.net = boost::asio::ip::address_v4(ntohl(row->dwForwardDest));
	entry.mask = boost::asio::ip::address_v4(ntohl(row->dwForwardMask));
	entry.metric = row->dwForwardMetric1;

	// find ifip.
	for (auto a = adapters.get(); a; a = a->Next)
	{
		for (auto gw = &a->GatewayList; gw; gw = gw->Next)
		{
			auto endp = boost::asio::ip::address_v4::from_string(std::string(gw->IpAddress.String));
			if (endp == entry.gateway)
			{
				auto ip = std::string(a->IpAddressList.IpAddress.String);
				if (!ip.empty())
				{
					entry.ifip = boost::asio::ip::address_v4::from_string(ip);
					return entry;
				}
			}
		}
	}

	return entry;
}



namespace win = boost::asio::windows;

struct tap_context
{
	dev_config cfg_;
	HANDLE handle_;
	char mac_addr_[6];
	int mtu_;
};



tuntap_window_device::tuntap_window_device(boost::asio::io_context& io)
	: m_io_context(io)
	, m_io_handle(io)
{
	auto default_gw = get_default_gateway();
	std::cout << "gateway: " << default_gw.gateway.to_string()
		<< ", net: " << default_gw.net.to_string()
		<< ", mask: " << default_gw.mask.to_string()
		<< ", if: " << default_gw.ifip.to_string()
		<< ", mertic: " << default_gw.metric << std::endl;

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
				std::cout << "component_id " << component_id
					<< ", net_cfg_instance_id " << tmp << std::endl;
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
				std::cout << "Name " << dev_name << std::endl;
			}
		}
	}

	for (auto& item : dev_map)
	{
		m_device_list.push_back(tap_device{ item.second, item.first });
	}
}

tuntap_window_device::~tuntap_window_device()
{
	close();
}

bool tuntap_window_device::open(const dev_config& cfg)
{
	int index;
	index = get_interface_index(cfg.guid_.c_str());

	TCHAR device_path[256] = { 0 };
	_stprintf(device_path, TEXT("%s%s%s"),
		USERMODEDEVICEDIR, cfg.guid_.c_str(), TAPSUFFIX);
	std::cout << device_path << std::endl;
	auto handle = CreateFile((LPCTSTR)device_path, GENERIC_READ | GENERIC_WRITE,
		0, 0, OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

	if (handle == INVALID_HANDLE_VALUE)
		return false;

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
	if (cfg.dev_type_ == dev_config::dev_tun
		&& version.major == 9 && version.minor < 8)
	{
		std::cout << "WARNING:  Tap-Win32 driver version " << version.major << "." << version.minor
			<< " does not support IPv6 in TUN mode. IPv6 will not work. Upgrade your Tap-Win32 driver.\n";
	}

	// tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy
	if (cfg.dev_type_ == dev_config::dev_tun
		&& version.major == 9 && version.minor == 8)
	{
		std::cout << "ERROR:  Tap-Win32 driver version " << version.major << "." << version.minor
			<< " is buggy regarding small IPv4 packets in TUN mode. Upgrade your Tap-Win32 driver.\n";
	}

 	if (cfg.dev_type_ == dev_config::dev_tun)
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
			auto ep1 = boost::asio::ip::address_v4(htonl(tun_addrs[1]));
			auto ep0 = boost::asio::ip::address_v4(htonl(tun_addrs[0]));
			auto ep2 = boost::asio::ip::address_v4(htonl(tun_addrs[2]));
			std::cout << "Set TAP-Windows TUN subnet mode network/local/netmask = " <<
				ep1.to_string() << "/" << ep0.to_string() << "/" << ep2.to_string() << std::endl;
		}
 	}
	else
	{
		netsh_ifconfig(
			cfg.local_,
			cfg.mask_,
			cfg.dev_name_);
	}

	// get mtu.
	ULONG mtu;
	if (DeviceIoControl(handle, TAP_IOCTL_GET_MTU,
		&mtu, sizeof(mtu),
		&mtu, sizeof(mtu), &len, NULL))
	{
		std::cout << "TAP-Windows MTU=" << mtu << std::endl;
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


#if 0
	uint32_t ep[4];

	ep[0] = inet_addr(cfg.local_.c_str());	// local ip
	ep[1] = inet_addr(cfg.mask_.c_str());	// mask
	ep[2] = inet_addr(cfg.dhcp_.c_str());

	inet_pton(AF_INET, cfg.local_.c_str(), &ep[0]);	// local ip
	inet_pton(AF_INET, cfg.mask_.c_str(), &ep[1]);	// mask
	inet_pton(AF_INET, cfg.dhcp_.c_str(), &ep[2]);

	ep[3] = 0x00FFFFFF;

	if (!DeviceIoControl(handle, TAP_IOCTL_CONFIG_DHCP_MASQ,
		ep, sizeof(ep), ep, sizeof(ep), &len, NULL))
	{
		CloseHandle(handle);
		return false;
	}
#endif

	if (!tap_win32_set_status(handle, TRUE))
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

	if (m_tap_context &&
		m_tap_context->handle_ != NULL &&
		m_tap_context->handle_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_tap_context->handle_);
	}

	m_tap_context = std::make_shared<tap_context>();
	m_tap_context->cfg_ = cfg;
	m_tap_context->handle_ = handle;
	m_tap_context->mtu_ = (int)mtu;
	std::memcpy(m_tap_context->mac_addr_, mac, 6);

	boost::system::error_code ec;
	m_io_handle.assign(handle, ec);
	if (ec)
	{
		std::cout << "Assign to random_access_handle: " << ec.message() << std::endl;
	}

	return true;
}

void tuntap_window_device::close()
{
	if (m_io_handle.is_open())
	{
		tap_win32_set_status(m_tap_context->handle_, FALSE);

		boost::system::error_code ignore_ec;
		m_io_handle.close(ignore_ec);
	}

	if (m_tap_context &&
		m_tap_context->handle_ != NULL &&
		m_tap_context->handle_ != INVALID_HANDLE_VALUE)
	{
		m_tap_context.reset();
	}
}

const std::vector<tap_device>& tuntap_window_device::fetch_tap_device_list()
{
	return m_device_list;
}

bool tuntap_window_device::fetch_mac(char mac[6])
{
	if (m_tap_context)
	{
		std::memcpy(mac, m_tap_context->mac_addr_, 6);
		return true;
	}

	return false;
}

int tuntap_window_device::fetch_mtu()
{
	return m_tap_context->mtu_;
}

