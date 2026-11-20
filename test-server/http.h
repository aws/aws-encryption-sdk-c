/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ESDK_TEST_SERVER_HTTP_H
#define ESDK_TEST_SERVER_HTTP_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace esdk_test_server {
namespace http {

struct Request {
    std::string method;
    std::string path;
    /** Header names are lower-cased; values are trimmed. */
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;

    const std::string *header(const std::string &lowercase_name) const;
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
};

using Handler = std::function<Response(const Request &)>;

/**
 * A minimal HTTP/1.1 server over POSIX sockets: keep-alive connections, one
 * thread per connection, Content-Length request bodies only (no chunked
 * transfer coding), 100-continue expectations honored.
 */
class Server {
   public:
    ~Server();

    /**
     * Binds 127.0.0.1:port and listens. Pass port 0 for an ephemeral port
     * (readable via port() afterwards). Returns false and sets *error on
     * failure.
     */
    bool bind(uint16_t port, std::string *error);

    uint16_t port() const {
        return port_;
    }

    /** Accepts connections until the process exits. Requires a prior bind(). */
    void serve_forever(Handler handler);

   private:
    int listen_fd_ = -1;
    uint16_t port_ = 0;
};

}  // namespace http
}  // namespace esdk_test_server

#endif  // ESDK_TEST_SERVER_HTTP_H
