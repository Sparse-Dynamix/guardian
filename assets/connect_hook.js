// Adapted from fritm (https://github.com/louisabraham/fritm).
// Templates: PORT, FILTER (JS expression), BIND_HOST (four IPv4 octets).
// IPv6 destinations are not hooked in v1.

var PORT = {{PORT}};

function filter(sa_family, addr, port) {
    return {{FILTER}};
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

            var connect_request = "CONNECT " + this.addr + ":" + this.port + " HTTP/1.0\n\n";
            var buf_send = Memory.allocUtf8String(connect_request);
            socket_send(this.sockfd.toInt32(), buf_send, connect_request.length, 0);
            var buf_recv = Memory.alloc(512);
            var recv_return = socket_recv(this.sockfd.toInt32(), buf_recv, 512, 0);

            while (recv_return == -1) {
                Thread.sleep(0.05);
                recv_return = socket_recv(this.sockfd.toInt32(), buf_recv, 512, 0);
            }
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
    var connect_p = Module.getExportByName(null, 'connect');
    var send_p = Module.getExportByName(null, 'send');
    var recv_p = Module.getExportByName(null, 'recv');
    hookConnect(connect_p, send_p, recv_p);
}
