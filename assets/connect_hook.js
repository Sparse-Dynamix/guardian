// Adapted from fritm (https://github.com/louisabraham/fritm).
// Templates: PORT, FILTER (JS expression), BIND_HOST (four IPv4 octets).
// IPv6 destinations are not hooked in v1.

var PORT = {{PORT}};

function globalExport(name) {
    if (typeof Module.getGlobalExportByName === 'function') {
        return Module.getGlobalExportByName(name);
    }
    if (typeof Module.findExportByName === 'function') {
        return Module.findExportByName(null, name);
    }
    return Module.getExportByName(null, name);
}

function filter(sa_family, addr, port) {
    return {{FILTER}};
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

function hookConnect(connect_p, send_p, recv_p) {
    var socket_send = new NativeFunction(send_p, 'int', ['int', 'pointer', 'int', 'int']);
    var socket_recv = new NativeFunction(recv_p, 'int', ['int', 'pointer', 'int', 'int']);

    Interceptor.attach(connect_p, {
        onEnter: function (args) {
            this.sockfd = args[0];
            var sockaddr_p = args[1];
            this.sa_family = sockaddr_p.add(1).readU8();
            this.port = 256 * sockaddr_p.add(2).readU8() + sockaddr_p.add(3).readU8();
            this.addr = "";
            for (var i = 0; i < 4; i++) {
                this.addr += sockaddr_p.add(4 + i).readU8();
                if (i < 3) this.addr += '.';
            }

            this.hook = filter(this.sa_family, this.addr, this.port);
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

            var connect_request = "CONNECT " + this.addr + ":" + this.port + " HTTP/1.1\r\n"
                + "Host: " + this.addr + ":" + this.port + "\r\n"
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
                    if (preview && preview.indexOf('\r\n\r\n') >= 0) {
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
    var wsaConnect = ws2.findExportByName('WSAConnect');
    if (wsaConnect) {
        hookConnect(
            wsaConnect,
            ws2.getExportByName('send'),
            ws2.getExportByName('recv')
        );
    }
} else {
    hookConnect(
        globalExport('connect'),
        globalExport('send'),
        globalExport('recv')
    );
}
