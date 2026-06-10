// Pure address bypass helpers (included in connect_hook.js; tested via scripts/connect-bypass.test.ts).

function isIpv4LoopbackOrUnspecified(bytes) {
    return bytes.length === 4
        && (bytes[0] === 127
            || (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0));
}

function isIpv4Mapped(bytes) {
    if (bytes.length !== 16) {
        return false;
    }
    for (var i = 0; i < 10; i++) {
        if (bytes[i] !== 0) {
            return false;
        }
    }
    return bytes[10] === 0xff && bytes[11] === 0xff;
}

function isIpv6LoopbackOrUnspecified(bytes) {
    if (bytes.length !== 16) {
        return false;
    }
    if (isIpv4Mapped(bytes)) {
        return isIpv4LoopbackOrUnspecified(bytes.slice(12, 16));
    }
    for (var i = 0; i < 15; i++) {
        if (bytes[i] !== 0) {
            return false;
        }
    }
    return bytes[15] === 0 || bytes[15] === 1;
}

function shouldBypassAddress(sa_family, bytes) {
    if (sa_family === 2) {
        return isIpv4LoopbackOrUnspecified(bytes);
    }
    if (sa_family === 10 || sa_family === 23) {
        return isIpv6LoopbackOrUnspecified(bytes);
    }
    return false;
}
