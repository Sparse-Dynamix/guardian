// Adapted from fritm (https://github.com/louisabraham/fritm) and HTTP Toolkit native-connect-hook.
// Templates: PORT, FILTER (JS expression), BIND_HOST, BIND_HOST_0..3 (IPv4 octets).
// IPv6 destinations are not hooked in v1.

var PORT = {{PORT}};
var BIND_HOST = "{{BIND_HOST}}";
var __guardianHostByIp = {};

function globalExport(name) {
    if (typeof Module.getGlobalExportByName === 'function') {
        return Module.getGlobalExportByName(name);
    }
    if (typeof Module.findExportByName === 'function') {
        return Module.findExportByName(null, name);
    }
    return Module.getExportByName(null, name);
}

function filter(sa_family, addr, port, host) {
    return {{FILTER}};
}

function connectTarget(ip) {
    if (__guardianHostByIp[ip]) {
        return __guardianHostByIp[ip];
    }
    return ip;
}

function rememberHostIp(host, ip) {
    if (host && ip) {
        __guardianHostByIp[ip] = host;
    }
}

function ipv4FromSockaddr(addrPtr) {
    var ip = "";
    for (var i = 0; i < 4; i++) {
        ip += addrPtr.add(4 + i).readU8();
        if (i < 3) {
            ip += '.';
        }
    }
    return ip;
}

function isStreamSocket(sockfd) {
    var sockType = Socket.type(sockfd);
    return sockType === 'tcp' || sockType === 'tcp6';
}

function mapAddrinfoResults(host, resPtr) {
    if (!host || resPtr.isNull()) {
        return;
    }
    var aiFamilyOff = 4;
    var aiAddrOff = Process.pointerSize === 8 ? 32 : 20;
    var aiNextOff = Process.pointerSize === 8 ? 48 : 28;
    var cur = resPtr;
    while (!cur.isNull()) {
        if (cur.add(aiFamilyOff).readS32() === 2) {
            var addr = cur.add(aiAddrOff).readPointer();
            if (!addr.isNull()) {
                rememberHostIp(host, ipv4FromSockaddr(addr));
            }
        }
        cur = cur.add(aiNextOff).readPointer();
    }
}

function hookResolveMap(name, fn, readHost) {
    if (!fn) {
        return;
    }
    Interceptor.attach(fn, {
        onEnter: function (args) {
            this.host = args[0].isNull() ? null : readHost(args[0]);
            this.resOut = args[3];
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0 || !this.host) {
                return;
            }
            mapAddrinfoResults(this.host, this.resOut.readPointer());
        }
    });
}

// attach-only getaddrinfo map: IP -> hostname for CONNECT authority (MITM cert SNI)
if (Process.platform === 'windows') {
    hookResolveMap(
        'GetAddrInfoW',
        globalExport('GetAddrInfoW'),
        function (p) { return p.readUtf16String(); }
    );
} else {
    hookResolveMap(
        'getaddrinfo',
        globalExport('getaddrinfo'),
        function (p) { return p.readUtf8String(); }
    );
}

function ensureBlockingSocket(sockfd) {
    if (Process.platform === 'windows') {
        return;
    }
    var fcntl = new NativeFunction(globalExport('fcntl'), 'int', ['int', 'int', 'int']);
    var F_GETFL = 3;
    var F_SETFL = 4;
    var O_NONBLOCK = 0x800;
    var flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    }
}

var recvCarry = {};

function storeCarry(sockfd, bytes) {
    if (!bytes || bytes.length === 0) {
        return;
    }
    var existing = recvCarry[sockfd];
    if (existing && existing.length > 0) {
        recvCarry[sockfd] = existing.concat(bytes);
    } else {
        recvCarry[sockfd] = bytes;
    }
}

function takeCarry(sockfd, maxLen) {
    var carry = recvCarry[sockfd];
    if (!carry || carry.length === 0) {
        return null;
    }
    var n = Math.min(carry.length, maxLen);
    var chunk = carry.slice(0, n);
    if (n < carry.length) {
        recvCarry[sockfd] = carry.slice(n);
    } else {
        delete recvCarry[sockfd];
    }
    return chunk;
}

function hookRecvCarry(recv_p) {
    Interceptor.attach(recv_p, {
        onEnter: function (args) {
            var fd = args[0].toInt32();
            var len = args[2].toInt32();
            if (len <= 0) {
                return;
            }
            var chunk = takeCarry(fd, len);
            if (!chunk) {
                return;
            }
            args[1].writeByteArray(chunk);
            this.replace(ptr(chunk.length));
        }
    });
}

function hookConnect(connect_p, send_p, recv_p) {
    var socket_send = new NativeFunction(send_p, 'int', ['int', 'pointer', 'int', 'int']);
    var socket_recv = new NativeFunction(recv_p, 'int', ['int', 'pointer', 'int', 'int']);

    Interceptor.attach(connect_p, {
        onEnter: function (args) {
            this.sockfd = args[0];
            var sockfd = this.sockfd.toInt32();
            if (!isStreamSocket(sockfd)) {
                this.hook = false;
                return;
            }

            var sockaddr_p = args[1];
            this.sa_family = sockaddr_p.add(1).readU8();
            this.port = 256 * sockaddr_p.add(2).readU8() + sockaddr_p.add(3).readU8();
            this.addr = ipv4FromSockaddr(sockaddr_p);

            if (this.sa_family != 2 && this.sa_family != 0) {
                this.hook = false;
                return;
            }

            if (this.addr === '127.0.0.1' || this.addr === '0.0.0.0') {
                this.hook = false;
                return;
            }

            if (this.addr === BIND_HOST && this.port === PORT) {
                this.hook = false;
                return;
            }

            var host = __guardianHostByIp[this.addr] || null;
            this.hook = filter(this.sa_family, this.addr, this.port, host);
            if (!this.hook) {
                return;
            }

            var newport = PORT;
            sockaddr_p.add(2).writeByteArray([Math.floor(newport / 256), newport % 256]);
            sockaddr_p.add(4).writeByteArray([{{BIND_HOST_0}}, {{BIND_HOST_1}}, {{BIND_HOST_2}}, {{BIND_HOST_3}}]);
        },
        onLeave: function (retval) {
            if (!this.hook) {
                return;
            }
            var sockfd = this.sockfd.toInt32();
            ensureBlockingSocket(sockfd);

            var target = connectTarget(this.addr);
            var connect_request = "CONNECT " + target + ":" + this.port + " HTTP/1.1\r\n"
                + "Host: " + target + ":" + this.port + "\r\n"
                + "Proxy-Connection: Keep-Alive\r\n"
                + "\r\n";
            var buf_send = Memory.allocUtf8String(connect_request);
            socket_send(sockfd, buf_send, connect_request.length, 0);

            var buf_recv = Memory.alloc(4096);
            var total = 0;
            var attempts = 0;
            while (total < 4096 && attempts < 200) {
                var recv_return = socket_recv(sockfd, buf_recv.add(total), 4096 - total, 0);
                if (recv_return > 0) {
                    total += recv_return;
                    var preview = buf_recv.readUtf8String(total);
                    var headerEnd = preview ? preview.indexOf('\r\n\r\n') : -1;
                    if (headerEnd >= 0) {
                        headerEnd += 4;
                        if (total > headerEnd) {
                            var leftover = buf_recv.add(headerEnd).readByteArray(total - headerEnd);
                            storeCarry(sockfd, Array.from(new Uint8Array(leftover)));
                        }
                        break;
                    }
                    continue;
                }
                if (recv_return === 0) {
                    break;
                }
                Thread.sleep(0.05);
                attempts++;
            }
            Thread.sleep(0.05);
        }
    });
}

if (Process.platform === 'windows') {
    var ws2 = Process.getModuleByName('ws2_32.dll');
    hookConnect(
        ws2.getExportByName('connect'),
        ws2.getExportByName('send'),
        ws2.getExportByName('recv')
    );
    hookRecvCarry(ws2.getExportByName('recv'));
    var wsaConnect = ws2.findExportByName('WSAConnect');
    if (wsaConnect) {
        hookConnect(
            wsaConnect,
            ws2.getExportByName('send'),
            ws2.getExportByName('recv')
        );
    }
} else {
    var recv_p = globalExport('recv');
    var read_p = globalExport('read');
    hookConnect(globalExport('connect'), globalExport('send'), recv_p);
    hookRecvCarry(recv_p);
    hookRecvCarry(read_p);
}

// Force http/1.1 ALPN so MITM TLS does not negotiate HTTP/2 (unsupported on this path).
(function hookClientAlpn() {
    var http1 = Memory.alloc(9);
    http1.writeByteArray([8, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]);
    var callbacks = [];

    function replaceAlpn(name) {
        var fn = globalExport(name);
        if (!fn) {
            return;
        }
        var orig = new NativeFunction(fn, 'int', ['pointer', 'pointer', 'uint']);
        var cb = new NativeCallback(function (ctx, _protos, _len) {
            return orig(ctx, http1, 9);
        }, 'int', ['pointer', 'pointer', 'uint']);
        callbacks.push(cb);
        Interceptor.replace(fn, cb);
    }

    replaceAlpn('SSL_CTX_set_alpn_protos');
    replaceAlpn('SSL_set_alpn_protos');
})();
