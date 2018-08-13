#include <iostream>
#include <iterator>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <deque>

#ifdef __linux__
#  include <sys/resource.h>
#  include <systemd/sd-daemon.h>
#elif _WIN32
#  include <fcntl.h>
#  include <io.h>
#  include <Windows.h>
#endif

// #include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/array.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "vpncore/socks_client.hpp"
#include "vpncore/tuntap.hpp"
#include "vpncore/avpn_acceptor.hpp"

using namespace tuntap_service;
using namespace avpncore;

using namespace boost::asio;

#ifdef AVPN_WINDOWS
namespace win = boost::asio::windows;
#endif

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;


int platform_init()
{
#if defined(WIN32) || defined(_WIN32)
	/* Disable the "application crashed" popup. */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
		SEM_NOOPENFILEERRORBOX);

#if defined(DEBUG) ||defined(_DEBUG)
	//	_CrtDumpMemoryLeaks();
	// 	int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	// 	flags |= _CRTDBG_LEAK_CHECK_DF;
	// 	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	// 	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
	// 	_CrtSetDbgFlag(flags);
#endif

#if !defined(__MINGW32__)
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	_setmode(0, _O_BINARY);
	_setmode(1, _O_BINARY);
	_setmode(2, _O_BINARY);

	/* Disable stdio output buffering. */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Enable minidump when application crashed. */
#elif defined(__linux__)
	rlimit of = { 50000, 100000 };
	if (setrlimit(RLIMIT_NOFILE, &of) < 0)
	{
		perror("setrlimit for nofile");
	}
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
	{
		perror("setrlimit for coredump");
	}
#endif

	return 0;
}

int main(int argc, char** argv)
{
	platform_init();

	io_context io;

	dev_config cfg = { "10.0.0.1", "255.255.255.0", "10.0.0.0" };
	// dev_config cfg = { "0.0.0.0", "255.255.255.255", "0.0.0.0" };

	cfg.dev_name_ = "VPN01";
	if (argc >= 2)
		cfg.dev_name_ = argv[1];

	tuntap tap(io);
	auto dev_list = tap.take_device_list();
	std::string guid;
	for (auto& i : dev_list)
	{
		if (i.name_ == cfg.dev_name_)
		{
			cfg.guid_ = i.guid_;
			break;
		}
	}

	streambuf read_buf;

#ifdef AVPN_LINUX
	cfg.dev_name_ = "";
	cfg.guid_ = "";
	cfg.dev_type_ = tuntap_service::dev_tun;
	cfg.tun_fd_ = -1;
#else
	cfg.dev_type_ = tuntap_service::dev_tun;
#endif
	if (!tap.open(cfg))
	{
		printf("open tun device fail!\n");
		return -1;
	}

	// 创建tun2socks对象.
	tun2socks ts(io, tap);

	// 启动tun2socks.
	ts.start("10.0.0.2", cfg.mask_, argv[2]);

	// running...
	io.run();

	return 0;
}
