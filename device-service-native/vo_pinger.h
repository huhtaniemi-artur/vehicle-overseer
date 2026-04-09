// vo_pinger.h — Vehicle Overseer device pinger. C++17, POSIX sockets, no deps.
// Single header. Define your device identity, include, start/stop.
//
// Build: g++ -std=c++17 -pthread your_app.cpp -o your_app
//
// Usage:
//   vo::Pinger p("http://10.0.0.1:3100", "AABBCCDDEEFF", "my-device",
//                []() -> std::string { return get_device_address(); });
//   std::thread t([&]{ p.run(); });
//   // ... later:
//   p.stop();
//   t.join();
//
// Log streaming (optional):
//   The backend can proxy logs from this device if a TCP server is listening
//   on the device at the port reported in data.logPort. The server just accepts
//   a connection and writes newline-delimited text — the backend bridges it to
//   WebSocket clients. This pinger does NOT implement that server; add your own
//   thread that binds to logPort and writes lines to accepted sockets.
//   Uncomment the log_port_ snippets below to advertise that port in pings.

#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace vo {

constexpr int DRAIN_TIMEOUT_MS = 1000;

// Called each ping to get the device's current reachable address (IPv4, IPv6, hostname, etc.).
// Return empty string to skip the ping (e.g. interface not ready).
using AddressCallback = std::function<std::string()>;

class Pinger {
public:
    // backend_url:  "http://host:port"
    // uid:          stable device identifier (MAC, serial, etc.)
    // label:        human-readable name shown in UI
    // address_cb:   called each ping to resolve current device address
    Pinger(const char* backend_url, const char* uid, const char* label,
           AddressCallback address_cb, int interval_s = 5)
        : uid_(uid), label_(label), address_cb_(std::move(address_cb)),
          interval_s_(interval_s)
    {
        std::string u(backend_url);
        auto p = u.find("://");
        if (p != std::string::npos) u = u.substr(p + 3);
        if (!u.empty() && u.back() == '/') u.pop_back();
        auto c = u.rfind(':');
        if (c != std::string::npos) { port_ = u.substr(c + 1); host_ = u.substr(0, c); }
        else { host_ = u; port_ = "3100"; }
    }

    void run() {
        running_ = true;
        while (running_) {
            ping();
            for (int i = 0; i < interval_s_ * 10 && running_; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void stop() { running_ = false; }

private:
    std::string host_, port_, uid_, label_;
    AddressCallback address_cb_;
    int interval_s_;
    // int log_port_;
    std::atomic<bool> running_{false};

    static bool readable(int fd, int timeout_ms) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        return ::select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0;
    }

    void ping() {
        std::string addr = address_cb_();
        if (addr.empty()) return;

        std::string body = "{\"uid\":\"" + uid_ + "\",\"label\":\"" + label_
            + "\",\"ip-address\":\"" + addr + "\"";
        // body += ",\"data\":{\"logPort\":" + std::to_string(log_port_) + "}";
        body += "}";

        std::string req = "POST /api/ping HTTP/1.1\r\nHost: " + host_ + "\r\n"
            "Content-Type: application/json\r\nContent-Length: "
            + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;

        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (::getaddrinfo(host_.c_str(), port_.c_str(), &hints, &res) != 0 || !res) return;

        int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { ::freeaddrinfo(res); return; }

        struct timeval tv{3, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (::connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
            ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
            ::shutdown(fd, SHUT_WR);
            char buf[256];
            while (readable(fd, DRAIN_TIMEOUT_MS) && ::recv(fd, buf, sizeof(buf), 0) > 0) {}
        }
        ::close(fd);
        ::freeaddrinfo(res);
    }
};

} // namespace vo
