/**
 * Copyright (C) 2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <virgil/iot/initializer/NetRequestSender.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ostream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstring>

using virgil::soraa::initializer::NetRequestSender;

const std::string NetRequestSender::kSocket("127.0.0.1");
const uint16_t NetRequestSender::kPort(3333);

int NetRequestSender::openSocketAndSendRequest(const std::string &request, size_t timeout) {
    struct sockaddr_in server;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (-1 == fd) {
        throw std::runtime_error(std::string("Can't open ") + kSocket);
    }

    server.sin_addr.s_addr = inet_addr(kSocket.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(kPort);

    if (connect(fd, (struct sockaddr*)&server, sizeof(server)) == -1) {
        throw std::runtime_error(std::string("Can't connect to ") + kSocket + ":" + std::to_string(kPort));
    }

    struct timeval tv;

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

#if 1
    std::cerr << "REQUEST: " << request << std::endl;
#endif

    if (request.length() != write(fd, request.c_str(), request.length())) {
        close(fd);
        throw std::runtime_error(std::string("Can't write to ") + kSocket);
    }

    return fd;
}

std::string NetRequestSender::readMultipleResponses(int fd) {
    uint8_t buf[5 * 1024];
    memset(buf, 0, sizeof(buf));

    ssize_t res;

    std::stringstream ss;

    do {
        res = read(fd, buf, sizeof(buf));

        if (res > 0) {
            ss << std::string(reinterpret_cast <char *> (buf));
        }
    } while (res > 0);

    close(fd);

    return ss.str();
}

std::string NetRequestSender::readLine(int fd) {
    std::string res;
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    ssize_t numRead;                    /* # of bytes fetched by last read() */
    size_t totRead;                     /* Total bytes read so far */
    char *buf;
    char ch;

    buf = buffer;                       /* No pointer arithmetic on "void *" */

    totRead = 0;
    while (true) {
        numRead = read(fd, &ch, 1);

        if (numRead == -1) {
            if (errno == EINTR) {       /* Interrupted --> restart read() */
                continue;
            } else {
                return res;   /* Some other error */
            }

        } else if (numRead == 0) {      /* EOF */
            if (totRead == 0) {         /* No bytes read; return 0 */
                return res;
            } else {                    /* Some bytes read; add '\0' */
                break;
            }

        } else {                        /* 'numRead' must be 1 if we get here */
            if (totRead < (sizeof(buffer) - 1)) {      /* Discard > (n - 1) bytes */
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n') {
                break;
            }
        }
    }

    return std::string(buffer);
}

std::string NetRequestSender::readSingleResponse(int fd) {
    auto res = readLine(fd);
    close(fd);
#if 0
        std::cout << res << std::endl;
#endif
    return res;
}

std::string NetRequestSender::netRequest(const std::string &request, size_t timeout) {
    int fd = NetRequestSender::openSocketAndSendRequest(request, timeout);

    return NetRequestSender::readSingleResponse(fd);
}

std::string NetRequestSender::netRequestMultiple(const std::string &request, size_t timeout) {
    int fd = NetRequestSender::openSocketAndSendRequest(request, timeout);

    return NetRequestSender::readMultipleResponses(fd);
}
