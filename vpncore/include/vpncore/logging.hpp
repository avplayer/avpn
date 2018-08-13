#ifndef LOGGING_HPP
#define LOGGING_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <clocale>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/make_shared.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <boost/thread/mutex.hpp>

//////////////////////////////////////////////////////////////////////////
#include <zlib.h>

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>
//////////////////////////////////////////////////////////////////////////

#if defined(_WIN32) || defined(WIN32)
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif // !WIN32_LEAN_AND_MEAN
#	include <mmsystem.h>
#	include <windows.h>
#	pragma comment(lib, "Winmm.lib")
#endif // _WIN32

#ifdef __linux__
#	include <systemd/sd-journal.h>
#endif // __linux__

namespace logging {

///内部使用的简易日志类.
// @begin example
//  #include "logging.hpp"
//  int main()
//  {
//     init_logging();
//     LOG_DEBUG << "Initialized.";
//     std::string result = do_something();
//     LOG_DEBUG << "do_something return : " << result;	// 输出do_something返回结果到日志.
//     ...
//  }
// @end example
#ifndef AVHTTP_LOG_FILE_NUM
#define AVHTTP_LOG_FILE_NUM 3
#endif

#ifndef AVHTTP_LOG_FILE_BUFFER
#define AVHTTP_LOG_FILE_BUFFER (107374182400)
#endif

namespace compress {

#ifndef GZ_SUFFIX
#define GZ_SUFFIX ".gz"
#endif
#define SUFFIX_LEN (sizeof(GZ_SUFFIX) - 1)
#define BUFLEN 16384
#define MAX_NAME_LEN 4096

	inline boost::mutex& compress_lock()
	{
		static boost::mutex lock;
		return lock;
	}

	inline bool do_compress_gz(const std::string& infile)
	{
		std::string outfile = infile + GZ_SUFFIX;

		gzFile out = gzopen(outfile.c_str(), "wb6f");
		if (!out)
			return false;
		typedef typename std::remove_pointer<gzFile>::type gzFileType;
		std::unique_ptr<gzFileType, decltype(&gzclose)> gz_closer(out, &gzclose);

		FILE* in = fopen(infile.c_str(), "rb");
		if (!in)
			return false;
		std::unique_ptr<FILE, decltype(&fclose)> FILE_closer(in, &fclose);

		char buf[BUFLEN];
		int len;

		for (;;) {
			len = (int)fread(buf, 1, sizeof(buf), in);
			if (ferror(in))
				return false;

			if (len == 0)
				break;

			int total = 0;
			int ret;
			while (total < len) {
				ret = gzwrite(out, buf + total, (unsigned)len - total);
				if (ret <= 0) {
					return false;	// detail error information see gzerror(out, &ret);
				}
				total += ret;
			}
		}

		return true;
	}

}

namespace aux {

	static const boost::uint64_t epoch = 116444736000000000L; /* Jan 1, 1601 */
	typedef union {
		boost::uint64_t ft_scalar;
#if defined(WIN32) || defined(_WIN32)

		FILETIME ft_struct;
#else
		timeval ft_struct;
#endif
	} LOGGING_FT;

	inline int64_t gettime()
	{
#if defined(WIN32) || defined(_WIN32)
		static int64_t system_start_time = 0;
		static int64_t system_current_time = 0;
		static uint32_t last_time = 0;

		auto tmp = timeGetTime();

		if (system_start_time == 0) {
			LOGGING_FT nt_time;
			GetSystemTimeAsFileTime(&(nt_time.ft_struct));
			int64_t tim = (__int64)((nt_time.ft_scalar - aux::epoch) / 10000i64);
			system_start_time = tim - tmp;
		}

		system_current_time += (tmp - last_time);
		last_time = tmp;
		return system_start_time + system_current_time;
#elif defined(__linux__)
		struct timeval tv;
		gettimeofday(&tv, NULL);
		return ((int64_t)tv.tv_sec * 1000000 + tv.tv_usec) / 1000;
#endif
	}
}

class auto_logger_file {
public:
	auto_logger_file() = default;
	~auto_logger_file() = default;

	typedef boost::shared_ptr<std::ofstream> ofstream_ptr;
	typedef std::map<std::string, ofstream_ptr> loglist;
	typedef std::map<std::string, loglist> typelist;

	enum : int64_t {
		max_file_num = AVHTTP_LOG_FILE_NUM,
		max_log_size = AVHTTP_LOG_FILE_BUFFER,
	};

	void open(const char* path)
	{
		m_log_path = path;
		m_log_size = 0;
	}

	std::string log_path() const
	{
		return m_log_path.string();
	}

	void write(const char* log_name, const char* str, std::streamsize size)
	{
		ofstream_ptr of;
		std::string prefix_name = std::string(log_name);
		if (prefix_name.empty())
			prefix_name = "main";
		if (m_log_path.empty())
			m_log_path = "./logs";
		std::string fn = make_filename(m_log_path.string(), prefix_name);
		typelist::iterator t = m_log_list.find(prefix_name);
		if (t == m_log_list.end()) {
			loglist tmp;
			m_log_list[prefix_name] = tmp;
			t = m_log_list.find(prefix_name);
		}
		loglist& list = t->second;
		loglist::iterator iter = list.find(fn);
		if (iter == list.end()) {
			for (iter = list.begin(); iter != list.end(); iter++) {
				if (iter->second && iter->second->is_open())
					iter->second->close();
			}
			of.reset(new std::ofstream);
			boost::filesystem::path branch_path = boost::filesystem::path(fn).branch_path();
			if (!boost::filesystem::exists(branch_path)) {
				boost::system::error_code ignore_ec;
				boost::filesystem::create_directories(boost::filesystem::path(fn).branch_path(), ignore_ec);
			}
			of->open(fn.c_str(), std::ios_base::out | std::ios_base::app);
			of->sync_with_stdio(false);
			std::string start_string = "\n\n\n*** starting log ***\n\n\n";
			of->write(start_string.c_str(), start_string.size());
			list.insert(std::make_pair(fn, of));
			if (list.size() > max_file_num) {
				iter = list.begin();
				fn = iter->first;
				ofstream_ptr f = iter->second;
				list.erase(iter);
				if (f && f->is_open())
					f->close();
				f.reset();
				boost::system::error_code ignore_ec;
				int size = static_cast<int>(boost::filesystem::file_size(fn, ignore_ec));
				if (!ignore_ec)
					m_log_size -= size;
				boost::async(boost::launch::async,
					[fn]() {
					std::string file = fn;
					boost::mutex& m = compress::compress_lock();
					boost::mutex::scoped_lock lock(m);
					if (!compress::do_compress_gz(fn))
						file = fn + GZ_SUFFIX;

					boost::system::error_code ignore_ec;
					boost::filesystem::remove(file, ignore_ec);
					if (ignore_ec)
						std::cout << "delete log failed: " << file
						<< ", error code: " << ignore_ec.message() << std::endl;
				});
			}
		} else {
			of = iter->second;
		}

		if (of->is_open()) {
			m_log_size += size;
			of->write(str, size);
			of->flush();
		}
	}

	std::string make_filename(const std::string& p = "", std::string log_name = "") const
	{
		boost::posix_time::ptime time = boost::posix_time::second_clock::local_time();
		boost::filesystem::path log_path = boost::filesystem::path(p) / log_name;
		if (m_last_day != boost::posix_time::not_a_date_time &&
			m_last_day.time_of_day().hours() == time.time_of_day().hours()) {
			log_path = log_path / m_last_filename;
			return log_path.string();
		}
		m_last_day = time;
		std::ostringstream oss;
		oss.sync_with_stdio(false);
		boost::posix_time::time_facet* _facet = new boost::posix_time::time_facet("%Y%m%d-%H");
		oss.imbue(std::locale(std::locale::classic(), _facet));
		oss << boost::posix_time::second_clock::local_time();
		if (!boost::filesystem::exists(log_path)) {
			boost::system::error_code ignore_ec;
			boost::filesystem::create_directories(log_path, ignore_ec);
		}
		m_last_filename = oss.str() + std::string(".log");
		log_path = log_path / m_last_filename;
		return log_path.string();
	}

private:
	boost::filesystem::path m_log_path;
	typelist m_log_list;
	int64_t m_log_size;
	mutable boost::posix_time::ptime m_last_day;
	mutable std::string m_last_filename;
};

namespace aux {

	template <class Lock>
	Lock& lock_single()
	{
		static Lock lock_instance;
		return lock_instance;
	}

	template <class Writer>
	Writer& writer_single()
	{
		static Writer writer_instance;
		return writer_instance;
	}

	inline std::string time_to_string(int64_t time)
	{
		std::string ret;
		std::time_t rawtime = time / 1000;
		struct tm* ptm = std::localtime(&rawtime);
		if (!ptm)
			return ret;
		char buffer[1024];
		std::sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
			ptm->tm_hour, ptm->tm_min, ptm->tm_sec, (int)(time % 1000));
		ret = buffer;
		return ret;
	}
}

#ifndef DISABLE_LOGGER_THREAD_SAFE
#define LOGGER_LOCKS_() boost::mutex::scoped_lock lock(aux::lock_single<boost::mutex>())
#else
#define LOGGER_LOCKS_() ((void)0)
#endif // LOGGER_THREAD_SAFE

#ifndef LOGGER_DBG_VIEW_
#if defined(WIN32) && (defined(LOGGER_DBG_VIEW) || defined(DEBUG) || defined(_DEBUG))
#define LOGGER_DBG_VIEW_(x)              \
	do {                                 \
		::OutputDebugStringA(x.c_str()); \
	} while (0)
#else
#define LOGGER_DBG_VIEW_(x) ((void)0)
#endif // WIN32 && LOGGER_DBG_VIEW
#endif // LOGGER_DBG_VIEW_

static std::string LOGGER_DEBUG_STR = "DEBUG";
static std::string LOGGER_INFO_STR = "INFO";
static std::string LOGGER_WARN_STR = "WARNING";
static std::string LOGGER_ERR_STR = "ERROR";
static std::string LOGGER_FILE_STR = "FILE";

inline void output_console(std::string& level, const std::string& prefix, const std::string& message)
{
#ifdef WIN32
	HANDLE handle_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(handle_stdout, &csbi);
	if (level == LOGGER_INFO_STR)
		SetConsoleTextAttribute(handle_stdout, FOREGROUND_GREEN);
	else if (level == LOGGER_DEBUG_STR)
		SetConsoleTextAttribute(handle_stdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	else if (level == LOGGER_WARN_STR)
		SetConsoleTextAttribute(handle_stdout, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
	else if (level == LOGGER_ERR_STR)
		SetConsoleTextAttribute(handle_stdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
	std::printf("%s", prefix.c_str());
	SetConsoleTextAttribute(handle_stdout, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE);
	std::printf("%s", message.c_str());
	SetConsoleTextAttribute(handle_stdout, csbi.wAttributes);
#else
	fmt::MemoryWriter out;
	if (level == LOGGER_INFO_STR)
		out << "\033[32m" << prefix << "\033[0m" << message;
	else if (level == LOGGER_DEBUG_STR)
		out << "\033[1;32m" << prefix << "\033[0m" << message;
	else if (level == LOGGER_WARN_STR)
		out << "\033[1;33m" << prefix << "\033[0m" << message;
	else if (level == LOGGER_ERR_STR)
		out << "\033[1;31m" << prefix << "\033[0m" << message;
	std::cout << out.str();
	std::cout.flush();
#endif
}

#ifdef USE_SYSTEMD_LOGGING
inline void output_systemd(const std::string& level, const std::string& message)
{
	if (level == LOGGER_INFO_STR)
		sd_journal_print(LOG_INFO, "%s", message.c_str());
	else if (level == LOGGER_DEBUG_STR)
		sd_journal_print(LOG_DEBUG, "%s", message.c_str());
	else if (level == LOGGER_WARN_STR)
		sd_journal_print(LOG_WARNING, "%s", message.c_str());
	else if (level == LOGGER_ERR_STR)
		sd_journal_print(LOG_ERR, "%s", message.c_str());
}
#endif // USE_SYSTEMD_LOGGING

inline void logger_writer(int64_t time, std::string log_name, std::string level,
	std::string message, bool disable_cout = false)
{
	LOGGER_LOCKS_();
	std::string prefix = aux::time_to_string(time) + std::string(" [") + level + std::string("]: ");
	std::string tmp = message + "\n";
	std::string whole = prefix + tmp;
#ifndef DISABLE_WRITE_LOGGING
	logging::aux::writer_single<logging::auto_logger_file>().write(log_name.c_str(), whole.c_str(), whole.size());
#endif // !DISABLE_WRITE_LOGGING
	LOGGER_DBG_VIEW_(whole);
#ifndef DISABLE_LOGGER_TO_CONSOLE
	if (!disable_cout)
		output_console(level, prefix, tmp);
#endif
#ifdef USE_SYSTEMD_LOGGING
	output_systemd(level, message);
#endif // USE_SYSTEMD_LOGGING
}

namespace aux {

	class logger_internal {
	public:
		logger_internal()
		{
		}
		~logger_internal()
		{
			if (m_main_thread.joinable()) {
				if (!m_io_service.stopped())
					m_io_service.stop();
				m_main_thread.join();
			}
		}

	public:
		void start()
		{
			m_main_thread = boost::thread(boost::bind(&logger_internal::main_thread, this));
		}

		void stop()
		{
			if (!m_io_service.stopped())
				m_io_service.stop();
		}

		void post_log(std::string log_name, std::string level,
			std::string message, bool disable_cout = false)
		{
			m_io_service.post(boost::bind(&logger_writer, aux::gettime(),
				log_name, level, message, disable_cout));
		}

	private:
		void main_thread()
		{
			boost::asio::io_service::work work(m_io_service);
			try {
				m_io_service.run();
			} catch (std::exception& e) {
				e.what();
			}
		}

	private:
		boost::asio::io_service m_io_service;
		boost::thread m_main_thread;
	};
}

inline boost::shared_ptr<aux::logger_internal>& fetch_log_obj()
{
	static boost::shared_ptr<aux::logger_internal> logger_obj_;
	return logger_obj_;
}

inline void init_logging(bool use_async = true, const std::string& path = "")
{
	auto_logger_file& file = aux::writer_single<logging::auto_logger_file>();
	if (!path.empty())
		file.open(path.c_str());

	auto& log_obj = fetch_log_obj();
	if (use_async && !log_obj) {
		log_obj.reset(new aux::logger_internal());
		log_obj->start();
	}
}

inline std::string log_path()
{
	auto_logger_file& file = aux::writer_single<logging::auto_logger_file>();
	return file.log_path();
}

inline void shutdown_logging()
{
	auto& log_obj = fetch_log_obj();
	if (log_obj) {
		log_obj->stop();
		log_obj.reset();
	}
}

inline bool& logging_flag()
{
	static bool logging_ = true;
	return logging_;
}

inline void toggle_logging()
{
	logging_flag() = !logging_flag();
}

class logger : boost::noncopyable {
public:
	template <class Value>
	logger(std::string& level, Value v, bool disable_cout = false)
		: level_(level)
		, m_disable_cout(disable_cout)
	{
		if (!logging_flag())
			return;
		out_ << v;
		log_name_ = out_.str();
		out_.clear();
	}
	~logger()
	{
		if (!logging_flag())
			return;
		std::string message = out_.str();
		if (fetch_log_obj())
			fetch_log_obj()->post_log(log_name_, level_, message, m_disable_cout);
		else
			logger_writer(aux::gettime(), log_name_, level_, message, m_disable_cout);
	}

	template <class T>
	inline logger& strcat_impl(T const& v)
	{
		if (!logging_flag())
			return *this;
		out_ << v;
		return *this;
	}

	inline logger& operator<<(bool v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(short v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(unsigned short v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(int v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(unsigned int v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(long v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(unsigned long v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(long long v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(float v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(double v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(long double v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(size_t v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(const std::string& v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(const char* v)
	{
		return strcat_impl(v);
	}
	inline logger& operator<<(const void *v)
	{
		if (!logging_flag())
			return *this;
		out_ << "0x" << fmt::pad(fmt::hex((std::size_t)v), 8, '0');
		return *this;
	}
	inline logger& operator<<(const boost::posix_time::ptime& p)
	{
		if (!logging_flag())
			return *this;

		if (!p.is_not_a_date_time())
		{
			auto date = p.date();
			auto time = p.time_of_day();
			out_ << fmt::pad(date.year(), 4, '0')			// year.
				<< "-" << fmt::pad(date.month(), 2, '0')	// month.
				<< "-" << fmt::pad(date.day(), 2, '0')		// day.
				<< " " << fmt::pad(time.hours(), 2, '0')	// hours.
				<< ":" << fmt::pad(time.minutes(), 2, '0')	// minutes.
				<< ":" << fmt::pad(time.seconds(), 2, '0');	// seconds.
			auto ms = time.total_milliseconds() % 1000;		// milliseconds.
			if (ms != 0)
				out_ << "." << fmt::pad(ms, 3, '0');
		}
		else
		{
			out_ << "NOT A DATE TIME";
		}

		return *this;
	}


	fmt::MemoryWriter out_;
	std::string& level_;
	std::string log_name_;
	bool m_disable_cout;
};

class empty_logger : boost::noncopyable {
public:
	template <class T>
	empty_logger& operator<<(T const& v)
	{
		return *this;
	}
};
} // namespace util

using logging::init_logging;
using logging::shutdown_logging;

#if (defined(DEBUG) || defined(_DEBUG) || defined(ENABLE_LOGGER)) && !defined(DISABLE_LOGGER)

#define TLOG_DBG(x) logging::logger(logging::LOGGER_DEBUG_STR, x)
#define TLOG_INFO(x) logging::logger(logging::LOGGER_INFO_STR, x)
#define TLOG_WARN(x) logging::logger(logging::LOGGER_WARN_STR, x)
#define TLOG_ERR(x) logging::logger(logging::LOGGER_ERR_STR, x)
#define TLOG_FILE(x) logging::logger(logging::LOGGER_FILE_STR, x, true)

#undef LOG_DBG
#undef LOG_INFO
#undef LOG_WARN
#undef LOG_ERR
#undef LOG_FILE

#define LOG_DBG TLOG_DBG("main")
#define LOG_INFO TLOG_INFO("main")
#define LOG_WARN TLOG_WARN("main")
#define LOG_ERR TLOG_ERR("main")
#define LOG_FILE TLOG_FILE("main")

#define VLOG_DBG LOG_DBG << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_INFO LOG_INFO << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_WARN LOG_WARN << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_ERR LOG_ERR << "(" << __FILE__ << ":" << __LINE__ << "): "
#define VLOG_FILE LOG_FILE << "(" << __FILE__ << ":" << __LINE__ << "): "

#else

#define LOG_DBG logging::empty_logger()
#define LOG_INFO logging::empty_logger()
#define LOG_WARN logging::empty_logger()
#define LOG_ERR logging::empty_logger()
#define LOG_FILE logging::empty_logger()

#define TLOG_DBG(x) logging::empty_logger()
#define TLOG_INFO(x) logging::empty_logger()
#define TLOG_WARN(x) logging::empty_logger()
#define TLOG_ERR(x) logging::empty_logger()
#define TLOG_FILE(x) logging::empty_logger()

#define VLOG_DBG LOG_DBG
#define VLOG_INFO LOG_INFO
#define VLOG_WARN LOG_WARN
#define VLOG_ERR LOG_ERR
#define VLOG_FILE LOG_FILE

#endif

#endif // LOGGING_HPP
