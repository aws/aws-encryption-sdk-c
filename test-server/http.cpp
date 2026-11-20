/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <thread>

namespace esdk_test_server {
namespace http {

namespace {

const size_t MAX_HEADER_BYTES = 64 * 1024;
const size_t MAX_BODY_BYTES   = 1024ULL * 1024 * 1024;

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string trim(const std::string &s) {
    size_t begin = s.find_first_not_of(" \t");
    if (begin == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t");
    return s.substr(begin, end - begin + 1);
}

bool send_all(int fd, const uint8_t *data, size_t len) {
    while (len > 0) {
        ssize_t sent = ::send(fd, data, len, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += sent;
        len -= static_cast<size_t>(sent);
    }
    return true;
}

bool send_string(int fd, const std::string &s) {
    return send_all(fd, reinterpret_cast<const uint8_t *>(s.data()), s.size());
}

void write_response(int fd, const Response &response, bool close_connection) {
    const char *reason = response.status == 200 ? "OK" : "Bad Request";
    std::string head   = "HTTP/1.1 " + std::to_string(response.status) + " " + reason + "\r\n";
    for (const auto &header : response.headers) {
        head += header.first + ": " + header.second + "\r\n";
    }
    head += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
    head += close_connection ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
    head += "\r\n";
    if (send_string(fd, head)) send_all(fd, response.body.data(), response.body.size());
}

void write_plain_error(int fd, const std::string &message) {
    std::string head =
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(message.size()) +
        "\r\nConnection: close\r\n\r\n";
    if (send_string(fd, head)) send_string(fd, message);
}

/**
 * Reads one request off the connection. Returns 1 on success, 0 on orderly
 * end of stream before any request bytes, -1 on a malformed request (a plain
 * 400 has been written).
 */
int read_request(int fd, std::vector<uint8_t> *buffer, Request *request) {
    // Fill *buffer until the header terminator; leftover bytes from the
    // previous request on this connection are already in it.
    size_t header_end;
    for (;;) {
        std::string view(buffer->begin(), buffer->end());
        header_end = view.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
        if (buffer->size() > MAX_HEADER_BYTES) {
            write_plain_error(fd, "request headers too large");
            return -1;
        }
        uint8_t chunk[8192];
        ssize_t got = ::recv(fd, chunk, sizeof(chunk), 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (got == 0) return 0;
        buffer->insert(buffer->end(), chunk, chunk + got);
    }

    std::string head(buffer->begin(), buffer->begin() + header_end);
    buffer->erase(buffer->begin(), buffer->begin() + header_end + 4);

    // Request line: METHOD SP PATH SP VERSION
    size_t line_end        = head.find("\r\n");
    std::string first_line = line_end == std::string::npos ? head : head.substr(0, line_end);
    size_t sp1             = first_line.find(' ');
    size_t sp2             = first_line.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1) {
        write_plain_error(fd, "malformed request line");
        return -1;
    }
    request->method = first_line.substr(0, sp1);
    request->path   = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
    request->headers.clear();

    size_t cursor = line_end == std::string::npos ? head.size() : line_end + 2;
    while (cursor < head.size()) {
        size_t next     = head.find("\r\n", cursor);
        std::string row = head.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        cursor          = next == std::string::npos ? head.size() : next + 2;
        size_t colon    = row.find(':');
        if (colon == std::string::npos) continue;
        request->headers[to_lower(trim(row.substr(0, colon)))] = trim(row.substr(colon + 1));
    }

    if (request->header("transfer-encoding")) {
        write_plain_error(fd, "chunked request bodies are not supported");
        return -1;
    }

    size_t content_length     = 0;
    const std::string *length = request->header("content-length");
    if (length) {
        char *parse_end      = nullptr;
        unsigned long long v = strtoull(length->c_str(), &parse_end, 10);
        if (parse_end == length->c_str() || *parse_end != '\0' || v > MAX_BODY_BYTES) {
            write_plain_error(fd, "invalid content-length");
            return -1;
        }
        content_length = static_cast<size_t>(v);
    }

    const std::string *expect = request->header("expect");
    if (expect && to_lower(*expect) == "100-continue") {
        if (!send_string(fd, "HTTP/1.1 100 Continue\r\n\r\n")) return 0;
    }

    while (buffer->size() < content_length) {
        uint8_t chunk[8192];
        ssize_t got = ::recv(fd, chunk, sizeof(chunk), 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (got == 0) return 0;
        buffer->insert(buffer->end(), chunk, chunk + got);
    }
    request->body.assign(buffer->begin(), buffer->begin() + content_length);
    buffer->erase(buffer->begin(), buffer->begin() + content_length);
    return 1;
}

void serve_connection(int fd, const Handler &handler) {
    std::vector<uint8_t> buffer;
    for (;;) {
        Request request;
        int status = read_request(fd, &buffer, &request);
        if (status <= 0) break;

        Response response = handler(request);

        const std::string *connection = request.header("connection");
        bool close_connection         = connection && to_lower(*connection) == "close";
        write_response(fd, response, close_connection);
        if (close_connection) break;
    }
    ::close(fd);
}

}  // namespace

const std::string *Request::header(const std::string &lowercase_name) const {
    auto it = headers.find(lowercase_name);
    return it == headers.end() ? nullptr : &it->second;
}

Server::~Server() {
    if (listen_fd_ >= 0) ::close(listen_fd_);
}

bool Server::bind(uint16_t port, std::string *error) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        *error = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        *error = std::string("bind 127.0.0.1:") + std::to_string(port) + ": " + std::strerror(errno);
        return false;
    }
    if (::listen(listen_fd_, 128) < 0) {
        *error = std::string("listen: ") + std::strerror(errno);
        return false;
    }

    socklen_t addr_len = sizeof(addr);
    if (::getsockname(listen_fd_, reinterpret_cast<struct sockaddr *>(&addr), &addr_len) < 0) {
        *error = std::string("getsockname: ") + std::strerror(errno);
        return false;
    }
    port_ = ntohs(addr.sin_port);
    return true;
}

void Server::serve_forever(Handler handler) {
    // Writes to a connection the peer already closed must surface as EPIPE,
    // not terminate the process.
    ::signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        std::thread(serve_connection, fd, handler).detach();
    }
}

}  // namespace http
}  // namespace esdk_test_server
