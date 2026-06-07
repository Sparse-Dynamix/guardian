// Append guardian CA trust env vars before exec/spawn of child processes.
// CA_ENV is templated from Rust as a JSON array of "KEY=value" strings.

const CA_ENV = {{CA_ENV_JSON}};

function globalExport(name) {
    if (typeof Module.getGlobalExportByName === 'function') {
        return Module.getGlobalExportByName(name);
    }
    if (typeof Module.findExportByName === 'function') {
        return Module.findExportByName(null, name);
    }
    return Module.getExportByName(null, name);
}

function parseEnvBlock(envp) {
    const map = {};
    if (envp.isNull()) {
        return map;
    }
    for (let i = 0; ; i++) {
        const entry = envp.add(i * Process.pointerSize).readPointer();
        if (entry.isNull()) {
            break;
        }
        const s = entry.readUtf8String();
        if (!s) continue;
        const eq = s.indexOf('=');
        if (eq < 0) continue;
        map[s.substring(0, eq)] = s.substring(eq + 1);
    }
    return map;
}

function envMapToBlock(map) {
    const keys = Object.keys(map).sort();
    const lines = keys.map(k => k + '=' + map[k]);
    lines.push(null);
    return lines;
}

function mergeEnv(existing, caPairs) {
    const map = parseEnvBlock(existing);
    for (const pair of caPairs) {
        const eq = pair.indexOf('=');
        if (eq < 0) continue;
        const key = pair.substring(0, eq);
        if (!(key in map)) {
            map[key] = pair.substring(eq + 1);
        }
    }
    return envMapToBlock(map);
}

function writeEnvp(block) {
    const strings = [];
    for (const line of block) {
        if (line === null) {
            break;
        }
        strings.push(line);
    }
    const ptrs = strings.map(function (s) {
        return Memory.allocUtf8String(s);
    });
    const envp = Memory.alloc(Process.pointerSize * (ptrs.length + 1));
    for (let i = 0; i < ptrs.length; i++) {
        envp.add(i * Process.pointerSize).writePointer(ptrs[i]);
    }
    envp.add(ptrs.length * Process.pointerSize).writePointer(ptr(0));
    return { envp: envp, ptrs: ptrs };
}

function hookExecve(name, fn) {
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter: function (args) {
            const envp = args[2];
            if (envp.isNull()) return;
            const merged = mergeEnv(envp, CA_ENV);
            const built = writeEnvp(merged);
            this.newEnv = built.envp;
            this._envKeepalive = built.ptrs;
            args[2] = this.newEnv;
        }
    });
}

function hookPosixSpawn(name, fn) {
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter: function (args) {
            const envpPtr = args[6];
            if (envpPtr.isNull()) return;
            const envp = envpPtr.readPointer();
            if (envp.isNull()) return;
            const merged = mergeEnv(envp, CA_ENV);
            const built = writeEnvp(merged);
            this.newEnv = built.envp;
            this._envKeepalive = built.ptrs;
            envpPtr.writePointer(this.newEnv);
        }
    });
}

function parseWideEnvBlock(ptr) {
    const map = {};
    if (ptr.isNull()) return map;
    let p = ptr;
    while (true) {
        const s = p.readUtf16String();
        if (!s || s.length === 0) break;
        const eq = s.indexOf('=');
        if (eq >= 0) {
            map[s.substring(0, eq)] = s.substring(eq + 1);
        }
        p = p.add((s.length + 1) * 2);
    }
    return map;
}

function wideEnvMapToBlock(map) {
    const keys = Object.keys(map).sort();
    let total = 2; // final double-null
    const strings = [];
    for (const k of keys) {
        const s = k + '=' + map[k];
        strings.push(s);
        total += (s.length + 1) * 2;
    }
    const mem = Memory.alloc(total);
    let offset = 0;
    for (const s of strings) {
        mem.add(offset).writeUtf16String(s);
        offset += (s.length + 1) * 2;
    }
    mem.add(offset).writeU16(0);
    return mem;
}

function mergeWideEnv(ptr, caPairs) {
    const map = parseWideEnvBlock(ptr);
    for (const pair of caPairs) {
        const eq = pair.indexOf('=');
        if (eq < 0) continue;
        const key = pair.substring(0, eq);
        if (!(key in map)) {
            map[key] = pair.substring(eq + 1);
        }
    }
    return wideEnvMapToBlock(map);
}

function hookCreateProcess(fn) {
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter: function (args) {
            const lpEnvironment = args[6];
            if (lpEnvironment.isNull()) {
                // NULL inherits the parent environment (already includes CA from spawn).
                return;
            }
            this.newEnv = mergeWideEnv(lpEnvironment, CA_ENV);
            args[6] = this.newEnv;
        }
    });
}

if (Process.platform === 'linux') {
    hookExecve('execve', globalExport('execve'));
    hookExecve('execveat', globalExport('execveat'));
    hookExecve('execvp', globalExport('execvp'));
    hookExecve('execvpe', globalExport('execvpe'));
} else if (Process.platform === 'darwin') {
    hookPosixSpawn('posix_spawn', globalExport('posix_spawn'));
    hookPosixSpawn('posix_spawnp', globalExport('posix_spawnp'));
    hookExecve('execve', globalExport('execve'));
} else if (Process.platform === 'windows') {
    const k32 = Process.getModuleByName('kernel32.dll');
    hookCreateProcess(k32.getExportByName('CreateProcessW'));
    const narrow = k32.findExportByName('CreateProcessA');
    if (narrow) {
        hookCreateProcess(narrow);
    }
}
