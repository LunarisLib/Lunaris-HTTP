#pragma once

#include "http.h"

namespace Lunaris {
    
    inline Http::e_error Http::open(const std::string& agent, const Http::e_proxy access, const std::string proxy,
        const std::string& proxy_bypass_list, const Http::e_open_sec open_sec)
    {
        if (proxy_bypass_list.size() && proxy.size() == 0) return Http::e_error::INVALID_ARGUMENTS;

        if (const auto good = close(); !good) return good;


        const auto w_agent = _wstr(agent);
        const auto w_proxy = _wstr(proxy);
        const auto w_proxy_bypass_list = _wstr(proxy_bypass_list);

        if (!(m_session = WinHttpOpen(w_agent.c_str(),
            _acast(access),
            w_proxy.size() ? w_proxy.c_str() : WINHTTP_NO_PROXY_NAME,
            w_proxy_bypass_list.size() ? w_proxy_bypass_list.c_str() : WINHTTP_NO_PROXY_BYPASS,
            static_cast<DWORD>(open_sec))))
        {
            switch (GetLastError()) {
            case ERROR_WINHTTP_INTERNAL_ERROR:
                return Http::e_error::INTERNAL_ERROR;
            case ERROR_NOT_ENOUGH_MEMORY:
                return Http::e_error::NOT_ENOUGH_MEMORY;
            default:
                return Http::e_error::UNKNOWN;
            }
        }

        return Http::e_error::NONE;
    }

    inline Http::e_error Http::connect(const std::string& servername, const INTERNET_PORT port)
    {
        if (!m_session) return Http::e_error::INVALID_STATE;
        if (m_connect && !close(_or(Http::e_drop::CONNECT, Http::e_drop::REQUEST))) return Http::e_error::INVALID_STATE;

        const auto w_servername = _wstr(servername);

        if (!(m_connect = WinHttpConnect(m_session, w_servername.c_str(), port, 0))) {
            switch (GetLastError()) {
            case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                return Http::e_error::INCORRECT_HANDLE_TYPE;
            case ERROR_WINHTTP_INTERNAL_ERROR:
                return Http::e_error::INTERNAL_ERROR;
            case ERROR_WINHTTP_INVALID_URL:
                return Http::e_error::INVALID_URL;
            case ERROR_WINHTTP_OPERATION_CANCELLED:
                return Http::e_error::OPERATION_CANCELLED;
            case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
                return Http::e_error::UNRECOGNIZED_SCHEME;
            case ERROR_WINHTTP_SHUTDOWN:
                return Http::e_error::SHUTDOWN;
            case ERROR_NOT_ENOUGH_MEMORY:
                return Http::e_error::NOT_ENOUGH_MEMORY;
            default:
                return Http::e_error::UNKNOWN;
            }
        }

        return Http::e_error::NONE;
    }

    inline Http::e_error Http::openRequest(const std::string& httpverb, const std::string& objname, const std::string httpver,
        const std::string& referer, const std::vector<std::string> accepttypes,
        const Http::e_open_req open_req)
    {
        if (!m_session || !m_connect) return Http::e_error::INVALID_STATE;
        if (m_request && !close(Http::e_drop::REQUEST)) return Http::e_error::INVALID_STATE;

        const auto w_httpverb = _wstr(httpverb);
        const auto w_objname = _wstr(objname);
        const auto w_httpver = _wstr(httpver);
        const auto w_referer = _wstr(referer);
        wchar_t** w_accepttypes = accepttypes.size() ? (new wchar_t* [accepttypes.size() + 1] {nullptr}) : nullptr;
        if (accepttypes.size() && !w_accepttypes) return Http::e_error::NOT_ENOUGH_MEMORY;

        const auto free_wacc = [&w_accepttypes, siz = accepttypes.size()] {
            if (!w_accepttypes) return;
            for (size_t p = 0; p < siz; ++p) {
                if (w_accepttypes[p])
                    delete[] w_accepttypes[p];
            }
            delete[] w_accepttypes;
            w_accepttypes = nullptr;
        };

        if (accepttypes.size() > 0) {
            for (size_t p = 0; p < accepttypes.size() + 1; ++p) {
                if (p == accepttypes.size()) w_accepttypes[p] = nullptr;
                else {
                    w_accepttypes[p] = new wchar_t[accepttypes[p].size() + 1];
                    if (memcpy_s(w_accepttypes[p], accepttypes[p].size() + 1, accepttypes[p].data(), accepttypes[p].size())) {
                        free_wacc();
                        return Http::e_error::NOT_ENOUGH_MEMORY;
                    }
                    w_accepttypes[p][accepttypes[p].size()] = '\0';
                }
            }
        }

        if (!(m_request = WinHttpOpenRequest(m_connect,
            w_httpver.c_str(),
            w_objname.c_str(),
            w_httpver.size() ? w_httpver.c_str() : nullptr,
            w_referer.size() ? w_referer.c_str() : nullptr,
            (LPCWSTR*)w_accepttypes,
            static_cast<DWORD>(open_req)))) {

            free_wacc(); // free up that thing
            switch (GetLastError()) {
            case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                return Http::e_error::INCORRECT_HANDLE_TYPE;
            case ERROR_WINHTTP_INTERNAL_ERROR:
                return Http::e_error::INTERNAL_ERROR;
            case ERROR_WINHTTP_INVALID_URL:
                return Http::e_error::INVALID_URL;
            case ERROR_WINHTTP_OPERATION_CANCELLED:
                return Http::e_error::OPERATION_CANCELLED;
            case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
                return Http::e_error::UNRECOGNIZED_SCHEME;
            case ERROR_NOT_ENOUGH_MEMORY:
                return Http::e_error::NOT_ENOUGH_MEMORY;
            case ERROR_WINHTTP_RESEND_REQUEST:
                return Http::e_error::RESEND_REQUEST;
            default:
                return Http::e_error::UNKNOWN;
            }
        }

        free_wacc(); // free up that thing
        return Http::e_error::NONE;
    }

    inline Http::e_error Http::sendRequest(const std::string& headers, std::vector<char> data)
    {
        if (!m_request) return Http::e_error::INVALID_STATE;

        const auto w_headers = _wstr(headers);

        if (!WinHttpSendRequest(m_request,
            w_headers.size() ? w_headers.c_str() : WINHTTP_NO_ADDITIONAL_HEADERS,
            static_cast<DWORD>(w_headers.size()),
            data.size() ? data.data() : WINHTTP_NO_REQUEST_DATA,
            static_cast<DWORD>(data.size()),
            static_cast<DWORD>(data.size()), 0)) {
            switch (GetLastError()) {
            case ERROR_WINHTTP_CANNOT_CONNECT:
                return Http::e_error::CANNOT_CONNECT;
            case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
                return Http::e_error::CLIENT_AUTH_CERT_NEEDED;
            case ERROR_WINHTTP_CONNECTION_ERROR:
                return Http::e_error::CONNECTION_ERROR;
            case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                return Http::e_error::INCORRECT_HANDLE_STATE;
            case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                return Http::e_error::INCORRECT_HANDLE_TYPE;
            case ERROR_WINHTTP_INTERNAL_ERROR:
                return Http::e_error::INTERNAL_ERROR;
            case ERROR_WINHTTP_INVALID_URL:
                return Http::e_error::INVALID_URL;
            case ERROR_WINHTTP_LOGIN_FAILURE:
                return Http::e_error::LOGIN_FAILURE;
            case ERROR_WINHTTP_NAME_NOT_RESOLVED:
                return Http::e_error::NAME_NOT_RESOLVED;
            case ERROR_WINHTTP_OPERATION_CANCELLED:
                return Http::e_error::OPERATION_CANCELLED;
            case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:
                return Http::e_error::RESPONSE_DRAIN_OVERFLOW;
            case ERROR_WINHTTP_SECURE_FAILURE:
                return Http::e_error::SECURE_FAILURE;
            case ERROR_WINHTTP_SHUTDOWN:
                return Http::e_error::SHUTDOWN;
            case ERROR_WINHTTP_TIMEOUT:
                return Http::e_error::TIMEOUT;
            case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
                return Http::e_error::UNRECOGNIZED_SCHEME;
            case ERROR_NOT_ENOUGH_MEMORY:
                return Http::e_error::NOT_ENOUGH_MEMORY;
            case ERROR_INVALID_PARAMETER:
                return Http::e_error::INVALID_PARAMETER;
            case ERROR_WINHTTP_RESEND_REQUEST:
                return Http::e_error::RESEND_REQUEST;
            default:
                return Http::e_error::UNKNOWN;
            }
        }

        return Http::e_error::NONE;
    }
    
    inline Http::e_error Http::receiveResponse()
    {
        if (!m_request) return Http::e_error::INVALID_STATE;
        if (!WinHttpReceiveResponse(m_request, 0)) {
            switch (GetLastError()) {
            case ERROR_WINHTTP_CANNOT_CONNECT:
                return Http::e_error::CANNOT_CONNECT;
            case ERROR_WINHTTP_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW:
                return Http::e_error::CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW;
            case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
                return Http::e_error::CLIENT_AUTH_CERT_NEEDED;
            case ERROR_WINHTTP_CONNECTION_ERROR:
                return Http::e_error::CONNECTION_ERROR;
            case ERROR_WINHTTP_HEADER_COUNT_EXCEEDED:
                return Http::e_error::HEADER_COUNT_EXCEEDED;
            case ERROR_WINHTTP_HEADER_SIZE_OVERFLOW:
                return Http::e_error::HEADER_SIZE_OVERFLOW;
            case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                return Http::e_error::INCORRECT_HANDLE_STATE;
            case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                return Http::e_error::INCORRECT_HANDLE_TYPE;
            case ERROR_WINHTTP_INTERNAL_ERROR:
                return Http::e_error::INTERNAL_ERROR;
            case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
                return Http::e_error::INVALID_SERVER_RESPONSE;
            case ERROR_WINHTTP_INVALID_URL:
                return Http::e_error::INVALID_URL;
            case ERROR_WINHTTP_LOGIN_FAILURE:
                return Http::e_error::LOGIN_FAILURE;
            case ERROR_WINHTTP_NAME_NOT_RESOLVED:
                return Http::e_error::NAME_NOT_RESOLVED;
            case ERROR_WINHTTP_OPERATION_CANCELLED:
                return Http::e_error::OPERATION_CANCELLED;
            case ERROR_WINHTTP_REDIRECT_FAILED:
                return Http::e_error::REDIRECT_FAILED;
            case ERROR_WINHTTP_RESEND_REQUEST:
                return Http::e_error::RESEND_REQUEST;
            case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:
                return Http::e_error::RESPONSE_DRAIN_OVERFLOW;
            case ERROR_WINHTTP_SECURE_FAILURE:
                return Http::e_error::SECURE_FAILURE;
            case ERROR_WINHTTP_TIMEOUT:
                return Http::e_error::TIMEOUT;
            case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
                return Http::e_error::UNRECOGNIZED_SCHEME;
            case ERROR_NOT_ENOUGH_MEMORY:
                return Http::e_error::NOT_ENOUGH_MEMORY;
            default:
                return Http::e_error::UNKNOWN;
            }
        }

        return Http::e_error::NONE;
    }

    inline size_t Http::hasReadData()
    {
        if (!m_request) return 0;
        DWORD siz{};
        if (!WinHttpQueryDataAvailable(m_request, &siz)) return 0;
        return static_cast<size_t>(siz);
    }

    inline Http::e_error Http::readData(std::vector<char>& data, size_t limit)
    {
        if (!m_request) return Http::e_error::INVALID_STATE;

        DWORD siz{};
        char buf[512]{};

        while(1) {
            if (!WinHttpQueryDataAvailable(m_request, &siz)) {
                switch (GetLastError()) {
                case ERROR_WINHTTP_CONNECTION_ERROR:
                    return Http::e_error::CONNECTION_ERROR;
                case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                    return Http::e_error::INCORRECT_HANDLE_STATE;
                case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                    return Http::e_error::INCORRECT_HANDLE_TYPE;
                case ERROR_WINHTTP_INTERNAL_ERROR:
                    return Http::e_error::INTERNAL_ERROR;
                case ERROR_WINHTTP_OPERATION_CANCELLED:
                    return Http::e_error::OPERATION_CANCELLED;
                case ERROR_WINHTTP_TIMEOUT:
                    return Http::e_error::TIMEOUT;
                case ERROR_NOT_ENOUGH_MEMORY:
                    return Http::e_error::NOT_ENOUGH_MEMORY;
                }
            }

            if (siz == 0) break;

            while (siz && (limit > 0)) {
                const DWORD sizcpy = siz > sizeof(buf) ? sizeof(buf) : siz;
                DWORD rdd{};

                if (!(WinHttpReadData(m_request, (LPVOID)buf, sizcpy > limit ? static_cast<DWORD>(limit) : sizcpy, &rdd))) {
                    switch (GetLastError()) {
                    case ERROR_WINHTTP_CONNECTION_ERROR:
                        return Http::e_error::CONNECTION_ERROR;
                    case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                        return Http::e_error::INCORRECT_HANDLE_STATE;
                    case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                        return Http::e_error::INCORRECT_HANDLE_TYPE;
                    case ERROR_WINHTTP_INTERNAL_ERROR:
                        return Http::e_error::INTERNAL_ERROR;
                    case ERROR_WINHTTP_OPERATION_CANCELLED:
                        return Http::e_error::OPERATION_CANCELLED;
                    case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:
                        return Http::e_error::RESPONSE_DRAIN_OVERFLOW;
                    case ERROR_WINHTTP_TIMEOUT:
                        return Http::e_error::TIMEOUT;
                    case ERROR_NOT_ENOUGH_MEMORY:
                        return Http::e_error::NOT_ENOUGH_MEMORY;
                    }
                }
                siz -= rdd;
                limit -= rdd;

                data.insert(data.end(), std::begin(buf), std::begin(buf) + rdd);
            }

        }

        return Http::e_error::NONE;
    }

    inline Http::e_error Http::readData(std::function<bool(const char*, const size_t)> data_in)
    {
        if (!m_request) return Http::e_error::INVALID_STATE;

        DWORD siz{};
        char buf[512]{};
        while (1) {
            if (!WinHttpQueryDataAvailable(m_request, &siz)) {
                switch (GetLastError()) {
                case ERROR_WINHTTP_CONNECTION_ERROR:
                    return Http::e_error::CONNECTION_ERROR;
                case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                    return Http::e_error::INCORRECT_HANDLE_STATE;
                case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                    return Http::e_error::INCORRECT_HANDLE_TYPE;
                case ERROR_WINHTTP_INTERNAL_ERROR:
                    return Http::e_error::INTERNAL_ERROR;
                case ERROR_WINHTTP_OPERATION_CANCELLED:
                    return Http::e_error::OPERATION_CANCELLED;
                case ERROR_WINHTTP_TIMEOUT:
                    return Http::e_error::TIMEOUT;
                case ERROR_NOT_ENOUGH_MEMORY:
                    return Http::e_error::NOT_ENOUGH_MEMORY;
                }
            }

            if (siz == 0) break;

            while (siz) {
                const DWORD sizcpy = siz > sizeof(buf) ? sizeof(buf) : siz;
                DWORD rdd{};

                if (!(WinHttpReadData(m_request, (LPVOID)buf, sizcpy, &rdd))) {
                    switch (GetLastError()) {
                    case ERROR_WINHTTP_CONNECTION_ERROR:
                        return Http::e_error::CONNECTION_ERROR;
                    case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
                        return Http::e_error::INCORRECT_HANDLE_STATE;
                    case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
                        return Http::e_error::INCORRECT_HANDLE_TYPE;
                    case ERROR_WINHTTP_INTERNAL_ERROR:
                        return Http::e_error::INTERNAL_ERROR;
                    case ERROR_WINHTTP_OPERATION_CANCELLED:
                        return Http::e_error::OPERATION_CANCELLED;
                    case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:
                        return Http::e_error::RESPONSE_DRAIN_OVERFLOW;
                    case ERROR_WINHTTP_TIMEOUT:
                        return Http::e_error::TIMEOUT;
                    case ERROR_NOT_ENOUGH_MEMORY:
                        return Http::e_error::NOT_ENOUGH_MEMORY;
                    }
                }
                siz -= rdd;

                if (!data_in(buf, rdd)) break;
            }

        }

        return Http::e_error::NONE;
    }

    inline Http::e_error Http::close()
    {
        return close(static_cast<Http::e_drop>(-1), true); // all
    }

    inline Http::e_error Http::close(const Http::e_drop flags, const bool tryall)
    {
        Http::e_error err = Http::e_error::NONE;

        if (_isset(flags, Http::e_drop::REQUEST) && m_request) {
            if (!WinHttpCloseHandle(m_request)) {
                switch (GetLastError()) {
                case ERROR_WINHTTP_SHUTDOWN:
                    if (!tryall) return Http::e_error::SHUTDOWN;
                    err = Http::e_error::SHUTDOWN;
                case ERROR_WINHTTP_INTERNAL_ERROR:
                    if (!tryall) return Http::e_error::INTERNAL_ERROR;
                    err = Http::e_error::INTERNAL_ERROR;
                case ERROR_NOT_ENOUGH_MEMORY:
                    if (!tryall) return Http::e_error::NOT_ENOUGH_MEMORY;
                    err = Http::e_error::NOT_ENOUGH_MEMORY;
                default:
                    if (!tryall) return Http::e_error::UNKNOWN;
                    err = Http::e_error::UNKNOWN;
                }
            }
            else m_request = nullptr;
        }

        if (_isset(flags, Http::e_drop::CONNECT) && m_connect) {
            if (!WinHttpCloseHandle(m_connect)) {
                switch (GetLastError()) {
                case ERROR_WINHTTP_SHUTDOWN:
                    if (!tryall) return Http::e_error::SHUTDOWN;
                    err = Http::e_error::SHUTDOWN;
                case ERROR_WINHTTP_INTERNAL_ERROR:
                    if (!tryall) return Http::e_error::INTERNAL_ERROR;
                    err = Http::e_error::INTERNAL_ERROR;
                case ERROR_NOT_ENOUGH_MEMORY:
                    if (!tryall) return Http::e_error::NOT_ENOUGH_MEMORY;
                    err = Http::e_error::NOT_ENOUGH_MEMORY;
                default:
                    if (!tryall) return Http::e_error::UNKNOWN;
                    err = Http::e_error::UNKNOWN;
                }
            }
            else m_connect = nullptr;
        }

        if (_isset(flags, Http::e_drop::SESSION) && m_session) {
            if (!WinHttpCloseHandle(m_session)) {
                switch (GetLastError()) {
                case ERROR_WINHTTP_SHUTDOWN:
                    if (!tryall) return Http::e_error::SHUTDOWN;
                    err = Http::e_error::SHUTDOWN;
                case ERROR_WINHTTP_INTERNAL_ERROR:
                    if (!tryall) return Http::e_error::INTERNAL_ERROR;
                    err = Http::e_error::INTERNAL_ERROR;
                case ERROR_NOT_ENOUGH_MEMORY:
                    if (!tryall) return Http::e_error::NOT_ENOUGH_MEMORY;
                    err = Http::e_error::NOT_ENOUGH_MEMORY;
                default:
                    if (!tryall) return Http::e_error::UNKNOWN;
                    err = Http::e_error::UNKNOWN;
                }
            }
            else m_session = nullptr;
        }

        return err;
    }


    inline Http::e_error HttpSimple::Get(const std::string& full_url, std::string& output)
    {
        std::vector<char> _tmp;
        const auto res = Get(full_url, _tmp);
        if (_tmp.size()) output = std::string(std::move(_tmp.begin()), std::move(_tmp.end()));
        return res;
    }

    inline Http::e_error HttpSimple::Get(const std::string & full_url, std::vector<char>& output)
    {
        if (!_hasany()) {
            if (const auto good = open("Lunaris/1.0"); !good) return good;
        }

        const size_t b4_0 = [&full_url] { if (strncmp(full_url.c_str(), "https://", 8) == 0) return 8; if (strncmp(full_url.c_str(), "http://", 7) == 0) return 7; return 0; }();
        const size_t b4_p = full_url.find('/', b4_0);

        if (b4_p == std::string::npos || b4_p < b4_0) return Http::e_error::INVALID_ARGUMENTS;

        const std::string b4 = full_url.substr(b4_0, b4_p - b4_0);
        const std::string af = full_url.substr(b4_p);

        if (const auto good = connect(b4); !good) return good;
        if (const auto good = openRequest("GET", af); !good) return good;
        if (const auto good = sendRequest(); !good) return good;
        if (const auto good = receiveResponse(); !good) return good;
        if (const auto good = readData(output); !good) return good;

        return Http::e_error::NONE;
    }

    inline Http::e_error HttpSimple::Get(const std::string & full_url, std::function<bool(const char*, const size_t)> output)
    {
        if (!_hasany()) {
            if (const auto good = open("Lunaris/1.0"); !good) return good;
        }

        const size_t b4_0 = [&full_url] { if (strncmp(full_url.c_str(), "https://", 8) == 0) return 8; if (strncmp(full_url.c_str(), "http://", 7) == 0) return 7; return 0; }();
        const size_t b4_p = full_url.find('/', b4_0);

        if (b4_p == std::string::npos || b4_p < b4_0) return Http::e_error::INVALID_ARGUMENTS;

        const std::string b4 = full_url.substr(b4_0, b4_p - b4_0);
        const std::string af = full_url.substr(b4_p);

        if (const auto good = connect(b4); !good) return good;
        if (const auto good = openRequest("GET", af); !good) return good;
        if (const auto good = sendRequest(); !good) return good;
        if (const auto good = receiveResponse(); !good) return good;
        if (const auto good = readData(output); !good) return good;

        return Http::e_error::NONE;
    }

}
