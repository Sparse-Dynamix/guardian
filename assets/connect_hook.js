// Adapted from fritm (https://github.com/louisabraham/fritm) and HTTP Toolkit native-connect-hook.
// Templates: PORT, FILTER, BIND_HOST, BIND_HOST_0..3, CONNECT_BYPASS_LIB, CONNECT_HANDSHAKE_LIB.

var PORT = {{PORT}};
var BIND_HOST = "{{BIND_HOST}}";
var __guardianHostByIp = {};

var IPv6_MAPPING_PREFIX = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
var PROXY_HOST_IPv4_BYTES = [{{BIND_HOST_0}}, {{BIND_HOST_1}}, {{BIND_HOST_2}}, {{BIND_HOST_3}}];
var PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX.concat(PROXY_HOST_IPv4_BYTES);

{{CONNECT_BYPASS_LIB}}
{{CONNECT_HANDSHAKE_LIB}}

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

function connectTarget(addrKey) {
    if (__guardianHostByIp[addrKey]) {
        return __guardianHostByIp[addrKey];
    }
    return addrKey;
}

function rememberHostIp(host, ip) {
    if (host && ip) {
        __guardianHostByIp[ip] = host;
    }
}

function areBytesEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (var i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}

function ipv4BytesFromSockaddr(addrPtr) {
    var bytes = [];
    for (var i = 0; i < 4; i++) {
        bytes.push(addrPtr.add(4 + i).readU8());
    }
    return bytes;
}

function ipv4StringFromBytes(bytes) {
    var ip = "";
    for (var i = 0; i < 4; i++) {
        ip += bytes[i];
        if (i < 3) {
            ip += '.';
        }
    }
    return ip;
}

function ipv4FromSockaddr(addrPtr) {
    return ipv4StringFromBytes(ipv4BytesFromSockaddr(addrPtr));
}

function ipv6BytesFromSockaddr(addrPtr) {
    var bytes = [];
    for (var i = 0; i < 16; i++) {
        bytes.push(addrPtr.add(8 + i).readU8());
    }
    return bytes;
}

function ipv6KeyFromBytes(bytes) {
    if (isIpv4Mapped(bytes)) {
        return bytes[12] + '.' + bytes[13] + '.' + bytes[14] + '.' + bytes[15];
    }
    var parts = [];
    for (var i = 0; i < 16; i += 2) {
        parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return '[' + parts.join(':') + ']';
}

function formatConnectAuthority(target, port) {
    if (target.charAt(0) === '[') {
        return target + ':' + port;
    }
    return target + ':' + port;
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
        var family = cur.add(aiFamilyOff).readS32();
        var addr = cur.add(aiAddrOff).readPointer();
        if (!addr.isNull()) {
            if (family === 2) {
                rememberHostIp(host, ipv4FromSockaddr(addr));
            } else if (family === 10 || family === 23) {
                rememberHostIp(host, ipv6KeyFromBytes(ipv6BytesFromSockaddr(addr)));
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

function setBlockingSocket(sockfd) {
    if (Process.platform === 'windows') {
        return null;
    }
    var fcntl = new NativeFunction(globalExport('fcntl'), 'int', ['int', 'int', 'int']);
    var F_GETFL = 3;
    var F_SETFL = 4;
    var O_NONBLOCK = 0x800;
    var flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    }
    return flags;
}

function restoreSocketFlags(sockfd, flags) {
    if (Process.platform === 'windows' || flags === null || flags < 0) {
        return;
    }
    var fcntl = new NativeFunction(globalExport('fcntl'), 'int', ['int', 'int', 'int']);
    var F_SETFL = 4;
    fcntl(sockfd, F_SETFL, flags);
}

function lastConnectError() {
    if (Process.platform === 'windows') {
        var WSAGetLastError = new NativeFunction(globalExport('WSAGetLastError'), 'int', []);
        return WSAGetLastError();
    }
    try {
        var errnoLoc = new NativeFunction(globalExport('__errno_location'), 'pointer', []);
        return errnoLoc().readS32();
    } catch (e) {
        return 0;
    }
}

function isConnectPendingError(err) {
    return err === 11 || err === 35 || err === 36 || err === 37 || err === 114 || err === 115
        || err === 10035 || err === 10036 || err === 10037;
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

function sendAll(sockfd, socket_send, text) {
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
        bytes.push(text.charCodeAt(i) & 0xff);
    }
    var buf = Memory.alloc(bytes.length);
    buf.writeByteArray(bytes);
    var sent = 0;
    while (sent < bytes.length) {
        var n = socket_send(sockfd, buf.add(sent), bytes.length - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += n;
    }
    return true;
}

function failConnect(retval, sockfd, originalFlags) {
    delete recvCarry[sockfd];
    restoreSocketFlags(sockfd, originalFlags);
    if (Process.platform === 'windows') {
        var WSASetLastError = new NativeFunction(globalExport('WSASetLastError'), 'void', ['int']);
        WSASetLastError(10054);
        var closesocket = new NativeFunction(globalExport('closesocket'), 'int', ['int']);
        closesocket(sockfd);
    } else {
        var shutdown = new NativeFunction(globalExport('shutdown'), 'int', ['int']);
        var close = new NativeFunction(globalExport('close'), 'int', ['int']);
        shutdown(sockfd, 2);
        close(sockfd);
        try {
            var errnoLoc = new NativeFunction(globalExport('__errno_location'), 'pointer', []);
            errnoLoc().writeS32(111);
        } catch (e) { }
    }
    retval.replace(-1);
}

function readConnectResponse(sockfd, socket_recv) {
    var buf = Memory.alloc(MAX_CONNECT_HEADER_BYTES);
    var total = 0;
    var attempts = 0;
    while (total < MAX_CONNECT_HEADER_BYTES && attempts < MAX_CONNECT_IDLE_RECV) {
        var recv_return = socket_recv(sockfd, buf.add(total), MAX_CONNECT_HEADER_BYTES - total, 0);
        if (recv_return > 0) {
            total += recv_return;
            var verdict = evaluateConnectResponse(bytesFromBuffer(buf, total));
            if (verdict.reason !== 'incomplete') {
                return verdict;
            }
            continue;
        }
        if (recv_return === 0) {
            break;
        }
        if (Process.platform === 'windows') {
            Thread.sleep(CONNECT_RECV_SLEEP_SEC);
        }
        attempts++;
    }
    return evaluateConnectResponse(total > 0 ? bytesFromBuffer(buf, total) : []);
}

function performSyntheticConnect(sockfd, socket_send, socket_recv, authority, retval, originalFlags) {
    var connect_request = "CONNECT " + authority + " HTTP/1.1\r\n"
        + "Host: " + authority + "\r\n"
        + "\r\n";
    if (!sendAll(sockfd, socket_send, connect_request)) {
        failConnect(retval, sockfd, originalFlags);
        return;
    }
    var verdict = readConnectResponse(sockfd, socket_recv);
    if (!verdict.ok) {
        failConnect(retval, sockfd, originalFlags);
        return;
    }
    if (verdict.leftover && verdict.leftover.length > 0) {
        storeCarry(sockfd, verdict.leftover);
    }
    restoreSocketFlags(sockfd, originalFlags);
}

function hookConnect(connect_p, send_p, recv_p) {
    var socket_send = new NativeFunction(send_p, 'int', ['int', 'pointer', 'int', 'int']);
    var socket_recv = new NativeFunction(recv_p, 'int', ['int', 'pointer', 'int', 'int']);

    Interceptor.attach(connect_p, {
        onEnter: function (args) {
            this.sockfd = args[0];
            var sockfd = this.sockfd.toInt32();
            var sockType = Socket.type(sockfd);
            var isTCP4 = sockType === 'tcp';
            var isTCP6 = sockType === 'tcp6';
            if (!isTCP4 && !isTCP6) {
                this.hook = false;
                return;
            }

            var sockaddr_p = args[1];
            this.port = 256 * sockaddr_p.add(2).readU8() + sockaddr_p.add(3).readU8();
            this.isIPv6 = isTCP6;

            if (isTCP4) {
                this.sa_family = 2;
                this.addrBytes = ipv4BytesFromSockaddr(sockaddr_p);
                this.addrKey = ipv4StringFromBytes(this.addrBytes);

                if (shouldBypassAddress(this.sa_family, this.addrBytes)) {
                    this.hook = false;
                    return;
                }
                if (this.addrKey === BIND_HOST && this.port === PORT) {
                    this.hook = false;
                    return;
                }
            } else {
                this.sa_family = 10;
                this.addrBytes = ipv6BytesFromSockaddr(sockaddr_p);
                this.addrKey = ipv6KeyFromBytes(this.addrBytes);

                if (shouldBypassAddress(this.sa_family, this.addrBytes)) {
                    this.hook = false;
                    return;
                }
                if (this.port === PORT && areBytesEqual(this.addrBytes, PROXY_HOST_IPv6_BYTES)) {
                    this.hook = false;
                    return;
                }
            }

            var host = __guardianHostByIp[this.addrKey] || null;
            this.hook = filter(this.sa_family, this.addrKey, this.port, host);
            if (!this.hook) {
                return;
            }

            var newport = PORT;
            sockaddr_p.add(2).writeByteArray([Math.floor(newport / 256), newport % 256]);
            if (isTCP4) {
                sockaddr_p.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
            } else {
                sockaddr_p.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
            }
        },
        onLeave: function (retval) {
            if (!this.hook) {
                return;
            }
            if (retval.toInt32() !== 0) {
                if (!isConnectPendingError(lastConnectError())) {
                    return;
                }
            }
            var sockfd = this.sockfd.toInt32();
            var originalFlags = setBlockingSocket(sockfd);

            var target = connectTarget(this.addrKey);
            var authority = formatConnectAuthority(target, this.port);
            performSyntheticConnect(sockfd, socket_send, socket_recv, authority, retval, originalFlags);
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
