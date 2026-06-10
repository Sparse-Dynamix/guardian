// Pure CONNECT response helpers (included in connect_hook.js; tested via scripts/connect-handshake.test.ts).

var MAX_CONNECT_HEADER_BYTES = 4096;
var MAX_CONNECT_IDLE_RECV = 200;
var CONNECT_RECV_SLEEP_SEC = 0.005;

function bytesFromBuffer(buf, total) {
    return Array.from(new Uint8Array(buf.readByteArray(total)));
}

function findHeaderEnd(bytes) {
    for (var i = 0; i + 3 < bytes.length; i++) {
        if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a
            && bytes[i + 2] === 0x0d && bytes[i + 3] === 0x0a) {
            return i;
        }
    }
    return -1;
}

function parseConnectStatus(headerBytes) {
    var text = '';
    for (var i = 0; i < headerBytes.length; i++) {
        text += String.fromCharCode(headerBytes[i]);
    }
    var lineEnd = text.indexOf('\r\n');
    if (lineEnd < 0) {
        return { ok: false, status: 0, reason: 'no_status_line' };
    }
    var line = text.substring(0, lineEnd);
    var match = /^HTTP\/1\.[01] ([0-9]{3})/.exec(line);
    if (!match) {
        return { ok: false, status: 0, reason: 'bad_status_line' };
    }
    var code = parseInt(match[1], 10);
    if (code < 200 || code >= 300) {
        return { ok: false, status: code, reason: 'non_success' };
    }
    return { ok: true, status: code, reason: 'ok' };
}

function evaluateConnectResponse(bytes) {
    var headerEnd = findHeaderEnd(bytes);
    if (headerEnd < 0) {
        return { ok: false, headerEnd: -1, leftover: [], reason: 'incomplete' };
    }
    var headerBytes = bytes.slice(0, headerEnd + 4);
    var parsed = parseConnectStatus(headerBytes);
    if (!parsed.ok) {
        return {
            ok: false,
            headerEnd: headerEnd,
            leftover: [],
            reason: parsed.reason,
            status: parsed.status
        };
    }
    return {
        ok: true,
        headerEnd: headerEnd,
        leftover: bytes.slice(headerEnd + 4),
        reason: 'ok',
        status: parsed.status
    };
}
