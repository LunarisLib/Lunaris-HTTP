#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winhttp.h>
#include <AtlBase.h>
#include <atlconv.h>
#include <string>
#include <vector>
#include <functional>

#pragma comment(lib, "winhttp.lib")

//void dodown(const std::wstring& url, const std::wstring& method = L"GET", const std::wstring path = L"/", const std::string& fpend = "OUT.TXT");

namespace Lunaris {

	class Http {
	public:
		enum class e_proxy : DWORD { 
			NONE	= WINHTTP_ACCESS_TYPE_NO_PROXY,
			NAMED	= WINHTTP_ACCESS_TYPE_NAMED_PROXY,
			AUTO	= WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
		};
		enum class e_open_sec : DWORD {
			ASYNC	= WINHTTP_FLAG_ASYNC,
			SECURE	= WINHTTP_FLAG_SECURE_DEFAULTS,
		};
		enum class e_open_req : DWORD {
			BYPASS_PROXY_CACHE	   = WINHTTP_FLAG_BYPASS_PROXY_CACHE,
			ESCAPE_DISABLE		   = WINHTTP_FLAG_ESCAPE_DISABLE,
			ESCAPE_DISABLE_QUERY   = WINHTTP_FLAG_ESCAPE_DISABLE_QUERY,
			ESCAPE_PERCENT		   = WINHTTP_FLAG_ESCAPE_PERCENT,
			NULL_CODEPAGE		   = WINHTTP_FLAG_NULL_CODEPAGE,
			REFRESH 			   = WINHTTP_FLAG_REFRESH,
			SECURE				   = WINHTTP_FLAG_SECURE
		};
		enum class e_error {
			NONE, UNKNOWN, INVALID_STATE, INVALID_ARGUMENTS,
			INTERNAL_ERROR, NOT_ENOUGH_MEMORY,
			SHUTDOWN,
			INCORRECT_HANDLE_TYPE, INVALID_URL, OPERATION_CANCELLED, UNRECOGNIZED_SCHEME,
			CANNOT_CONNECT,
			CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW,
			CLIENT_AUTH_CERT_NEEDED,
			CONNECTION_ERROR,
			HEADER_COUNT_EXCEEDED,
			HEADER_SIZE_OVERFLOW,
			INCORRECT_HANDLE_STATE,
			INVALID_SERVER_RESPONSE,
			LOGIN_FAILURE,
			NAME_NOT_RESOLVED,
			REDIRECT_FAILED,
			RESEND_REQUEST,
			RESPONSE_DRAIN_OVERFLOW,
			SECURE_FAILURE,
			TIMEOUT,
			INVALID_PARAMETER
		};
	protected:
		constexpr std::wstring _wstr(const std::string& s) { return s.size() ? std::wstring(CA2W(s.c_str())) : L""; }
		constexpr std::string _sstr(const std::wstring& s) { return s.size() ? std::string(CW2A(s.c_str())) : ""; }

		constexpr DWORD _acast(const e_proxy& e) { return static_cast<DWORD>(e); }
		constexpr DWORD _acast(const e_open_sec& e) { return static_cast<DWORD>(e); }
		constexpr DWORD _acast(const e_open_req& e) { return static_cast<DWORD>(e); }
	public:
		e_error open(const std::string& agent, const e_proxy access = e_proxy::AUTO, const std::string proxy = {},
			const std::string& proxy_bypass_list = {}, const e_open_sec open_sec = static_cast<e_open_sec>(0));

		e_error connect(const std::string& servername, const INTERNET_PORT port = INTERNET_DEFAULT_PORT);

		e_error openRequest(const std::string& httpverb, const std::string& objname, const std::string httpver = {},
			const std::string& referer = {}, const std::vector<std::string> accepttypes = {},
			const Http::e_open_req open_req = static_cast<e_open_req>(0));

		e_error sendRequest(const std::string& headers = {}, std::vector<char> data = {});

		e_error receiveResponse();

		size_t hasReadData();
		e_error readData(std::vector<char>& data, size_t limit = static_cast<size_t>(-1));
		e_error readData(std::function<bool(const char*, const size_t)> data_in);

		e_error close();
	protected:
		enum class e_drop : uint8_t { SESSION = 1 << 0, CONNECT = 1 << 1, REQUEST = 1 << 2 };

		e_error close(const Http::e_drop flags, const bool tryall = true);

		HINTERNET m_session{};
		HINTERNET m_connect{};
		HINTERNET m_request{};

		constexpr bool _hasany() { return m_session || m_connect; }

		constexpr Http::e_drop _or(const Http::e_drop& a, const Http::e_drop& b)  { return static_cast<Http::e_drop>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b)); }
		constexpr bool _isset(const Http::e_drop& a, const Http::e_drop& b) { return static_cast<uint8_t>(a) & static_cast<uint8_t>(b); }
	};

	class HttpSimple : protected Http {
	public:
		using Http::open;
		Http::e_error Get(const std::string& full_url, std::string& output);
		Http::e_error Get(const std::string& full_url, std::vector<char>& output);
		Http::e_error Get(const std::string& full_url, std::function<bool(const char*, const size_t)> data_in);
	};

	constexpr bool operator!(const Http::e_error& e) { return e != Http::e_error::NONE; }
	constexpr bool operator+(const Http::e_error& e) { return e == Http::e_error::NONE; }

	constexpr Http::e_open_sec operator|(const Http::e_open_sec& a, const Http::e_open_sec& b) { return static_cast<Http::e_open_sec>(static_cast<DWORD>(a) | static_cast<DWORD>(b)); }
	constexpr Http::e_open_req operator|(const Http::e_open_req& a, const Http::e_open_req& b) { return static_cast<Http::e_open_req>(static_cast<DWORD>(a) | static_cast<DWORD>(b)); }
}

#include "http.ipp"