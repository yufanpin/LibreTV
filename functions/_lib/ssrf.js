// functions/_lib/ssrf.js
// ============================================================
// SSRF（服务端请求伪造）防护模块
// 同时兼容 Cloudflare Workers/Pages Functions 与 Node.js 18+（ESM）
// 由 functions/proxy/[[path]].js 与 server.mjs 共享，统一出网 URL 校验。
//
// 防护目标：
//   1. 协议白名单（仅 http/https）
//   2. 主机名黑名单（localhost、常见内网/云元数据主机名、单标签裸名）
//   3. IP 字面量全格式解析：IPv4 各种混淆写法（十进制/八进制/十六进制/
//      单整数/混合段）先规范化再校验私网/保留段；IPv6 压缩形式同样处理
//   4. 可选 DoH 严格模式：对域名做 DNS-over-HTTPS 解析，任一结果解析到
//      私网/保留地址即拦截（抵御 DNS rebinding）
// ============================================================

// ---------- 模块级状态 ----------

let dohEnabled = false; // 是否启用 DoH 严格校验

// DoH 解析结果缓存（hostname → { t, blocked }），TTL 60 秒，避免频繁 DoH 请求
const DOH_CACHE = new Map();
const DOH_TTL = 60 * 1000;
const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

/** 启用/关闭 DoH 严格校验（CF Pages 函数在初始化时按 env.SSRF_DOH 调用） */
export function setSsrFfDohEnabled(enabled) {
    dohEnabled = !!enabled;
}

/** 查询当前 DoH 严格校验开关 */
export function getSsrFfDohEnabled() {
    return dohEnabled;
}

// Node 环境：模块加载时自动读取 SSRF_DOH 环境变量
if (typeof process !== 'undefined' && process.env && process.env.SSRF_DOH === '1') {
    dohEnabled = true;
}

// ---------- IPv4 解析（处理所有混淆写法） ----------

/**
 * 将任意写法的 IPv4 规范化为点分十进制字符串。
 * 支持：点分十进制、八进制（前导 0）、十六进制（0x）、
 * 单整数形式（如 2130706433 = 127.0.0.1）、1-4 段混合写法。
 * 段解析规则（RFC 3986/inet_aton 语义）：
 *   - 以 0x 开头 → 十六进制
 *   - 以 0 开头且不止一位 → 八进制
 *   - 其余纯数字 → 十进制
 * 各段数值上限按位置校验（1 段 32 位、2 段低 24 位、3 段低 16 位、4 段各 8 位）。
 * 无法解析时返回 null（调用方将其视为域名而非 IP）。
 */
export function normalizeIPv4(input) {
    const host = String(input).trim();
    if (!host || host.length === 0 || host.length > 31) return null;

    const parts = host.split('.');
    if (parts.length === 0 || parts.length > 4) return null;

    const values = [];
    for (const part of parts) {
        if (part === '') return null; // 空段
        let value;
        if (/^0[xX]/.test(part)) {
            // 十六进制段
            const hex = part.slice(2);
            if (!/^[0-9a-fA-F]{1,8}$/.test(hex)) return null;
            value = parseInt(hex, 16);
        } else if (part.length > 1 && part.startsWith('0')) {
            // 八进制段（前导 0 一律按八进制解析，这是常见绕过点）
            if (!/^[0-7]+$/.test(part)) return null;
            value = parseInt(part, 8);
        } else if (/^\d+$/.test(part)) {
            // 十进制段
            value = parseInt(part, 10);
        } else {
            // 含字母且非 0x 前缀 → 不是 IP，视为域名
            return null;
        }
        if (!Number.isFinite(value) || value > 0xffffffff) return null;
        values.push(value);
    }

    let total;
    switch (values.length) {
        case 1:
            // 单整数形式（32 位）
            total = values[0];
            break;
        case 2:
            // A.B：A 高 8 位，B 低 24 位（如 127.1 = 127.0.0.1）
            if (values[0] > 0xff || values[1] > 0xffffff) return null;
            total = values[0] * 0x1000000 + values[1];
            break;
        case 3:
            // A.B.C：A、B 各 8 位，C 低 16 位（如 192.168.1 = 192.168.0.1）
            if (values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff) return null;
            total = values[0] * 0x1000000 + values[1] * 0x10000 + values[2];
            break;
        default:
            // 标准 A.B.C.D，各 8 位
            if (values.some((v) => v > 0xff)) return null;
            total = values[0] * 0x1000000 + values[1] * 0x10000 + values[2] * 0x100 + values[3];
            break;
    }

    return [
        (total >>> 24) & 0xff,
        (total >>> 16) & 0xff,
        (total >>> 8) & 0xff,
        total & 0xff
    ].join('.');
}

// ---------- IPv6 解析 ----------

/** 解析单个 IPv6 hextet，非法返回 null */
function parseHextet(part) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
    return parseInt(part, 16);
}

/**
 * 将 IPv6 压缩表示展开为 8 组规范小写 hex 字符串数组。
 * 支持 :: 压缩与 IPv4 尾部（::ffff:a.b.c.d）。
 * 非法时返回 null。
 */
function expandIPv6(host) {
    let h = host;
    // 处理 IPv4 尾部（最后一段含 '.'）
    const dotIdx = h.lastIndexOf('.');
    if (dotIdx !== -1) {
        const lastColon = h.lastIndexOf(':');
        if (lastColon === -1 || lastColon > dotIdx) return null;
        const v4 = normalizeIPv4(h.slice(lastColon + 1));
        if (!v4) return null;
        const [a, b, c, d] = v4.split('.').map(Number);
        const hex4 = ((a << 8) | b).toString(16) + ':' + ((c << 8) | d).toString(16);
        // 末尾可能紧跟 '::'（如 ::ffff:127.0.0.1），保留压缩标记
        const tail = lastColon > 0 && h.slice(0, lastColon).endsWith(':') ? '::' : ':';
        h = h.slice(0, lastColon) + tail + hex4;
    }

    const doubleColonIdx = h.indexOf('::');
    let groups;
    if (doubleColonIdx !== -1) {
        if (h.indexOf('::', doubleColonIdx + 1) !== -1) return null; // 多个 ::
        const left = h.slice(0, doubleColonIdx).split(':').filter(Boolean).map(parseHextet);
        const right = h.slice(doubleColonIdx + 2).split(':').filter(Boolean).map(parseHextet);
        if (left.some((g) => g === null) || right.some((g) => g === null)) return null;
        const missing = 8 - left.length - right.length;
        if (missing < 1) return null; // :: 至少代表一个组
        groups = [...left, ...new Array(missing).fill(0), ...right];
    } else {
        groups = h.split(':').map(parseHextet);
        if (groups.some((g) => g === null)) return null;
    }

    if (groups.length !== 8) return null;
    return groups.map((g) => g.toString(16).padStart(4, '0'));
}

/** 对 IPv6 规范形式分类，返回 'public' | 'private' | 'loopback' | 'unspecified' | 'link-local' | 'ula' | 'multicast' | 'invalid' */
function classifyIPv6(host) {
    const groups = expandIPv6(String(host).trim());
    if (!groups) return 'invalid';
    const g = groups.map((x) => parseInt(x, 16));

    const allZero = g.every((x) => x === 0);
    if (allZero) return 'unspecified';

    // ::1 回环
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
        return 'loopback';
    }
    // IPv4 映射 ::ffff:a.b.c.d
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
        const ip = `${(g[6] >>> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >>> 8) & 0xff}.${g[7] & 0xff}`;
        return isPrivateIPv4(ip) ? 'private' : 'public';
    }
    // ULA fc00::/7（fc00-fdff）
    if ((g[0] & 0xfe00) === 0xfc00) return 'ula';
    // 链路本地 fe80::/10（fe80-febf）
    if ((g[0] & 0xffc0) === 0xfe80) return 'link-local';
    // 组播 ff00::/8
    if ((g[0] & 0xff00) === 0xff00) return 'multicast';
    return 'public';
}

// ---------- 私有/保留网段判断 ----------

/** 判断规范点分十进制 IPv4 是否属于私网/保留/元数据段 */
function isPrivateIPv4(canonical) {
    const [a, b, c] = canonical.split('.').map(Number);
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 回环 127.0.0.0/8
    if (a === 169 && b === 254) return true; // 链路本地 169.254.0.0/16（含云元数据 169.254.169.254）
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    if (a === 192 && b === 0 && (c === 0 || c === 1 || c === 2)) return true; // 192.0.0.0/24、192.0.1.0/24、192.0.2.0/24（TEST-NET-1）
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 基准测试
    if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24（TEST-NET-2）
    if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24（TEST-NET-3）
    if (a >= 224) return true; // 组播 224.0.0.0/4 与保留 240.0.0.0/4
    return false;
}

/**
 * 判断 IP 是否属于私网/保留/回环/链路本地/元数据网段。
 * 入参可为任意 IPv4 混淆写法或（压缩）IPv6 字符串。
 * 非合法 IP 或公网地址返回 false。
 */
export function isPrivateIP(ip) {
    const value = String(ip).trim();
    if (!value) return false;
    if (value.includes(':')) {
        const cls = classifyIPv6(value);
        return cls === 'private' || cls === 'loopback' || cls === 'link-local' || cls === 'ula' || cls === 'unspecified' || cls === 'multicast';
    }
    const canonical = normalizeIPv4(value);
    if (!canonical) return false;
    return isPrivateIPv4(canonical);
}

// ---------- URL 字面量校验 ----------

const BLOCKED_HOSTNAMES = new Set(['localhost', '0.0.0.0', '::1', 'metadata', 'instance-data']);

/** 主机名后缀黑名单（内网/自动发现/保留域名空间） */
const BLOCKED_SUFFIXES = ['.local', '.internal', '.lan', '.home.arpa', '.localdomain', '.corp', '.localhost', '.invalid', '.test'];

/**
 * URL 字面量校验（同步）：协议白名单 + 主机名/IP 私网黑名单。
 * 通过不代表最终放行——域名还需在 checkUpstreamAllowed 中做 DoH 解析校验。
 */
export function isValidProxyUrl(urlString) {
    try {
        const parsed = new URL(urlString);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

        let host = parsed.hostname;
        if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1); // 去掉 IPv6 方括号

        const lower = host.toLowerCase();
        if (BLOCKED_HOSTNAMES.has(lower)) return false;
        for (const suffix of BLOCKED_SUFFIXES) {
            if (lower.endsWith(suffix)) return false;
        }

        if (lower.includes(':')) {
            // IPv6 字面量
            const cls = classifyIPv6(lower);
            if (cls === 'invalid') return false;
            return cls === 'public';
        }

        // 纯数字/hex/点字符才可能是 IPv4 字面量（含各种混淆写法）
        if (/^[0-9a-fA-F.x]+$/.test(lower)) {
            const canonical = normalizeIPv4(lower);
            if (canonical) {
                return !isPrivateIPv4(canonical);
            }
            // 解析失败（如 "dead.beef"）→ 视为域名，不在此拦截
        }

        return true;
    } catch {
        return false;
    }
}

// ---------- DoH 解析校验 ----------

/** 通过 Cloudflare DoH 解析主机名的 A/AAAA 记录，返回 { records, failures } */
async function resolveViaDoh(hostname) {
    const records = [];
    let failures = 0;

    const results = await Promise.allSettled([
        fetch(`${DOH_ENDPOINT}?name=${encodeURIComponent(hostname)}&type=A`, { headers: { accept: 'application/dns-json' } }),
        fetch(`${DOH_ENDPOINT}?name=${encodeURIComponent(hostname)}&type=AAAA`, { headers: { accept: 'application/dns-json' } })
    ]);

    for (const result of results) {
        if (result.status !== 'fulfilled') {
            failures++;
            continue;
        }
        const response = result.value;
        if (!response.ok) {
            failures++;
            continue;
        }
        try {
            const json = await response.json();
            if (Array.isArray(json.Answer)) {
                for (const record of json.Answer) {
                    if (typeof record.data === 'string' && (record.type === 1 || record.type === 28)) {
                        records.push(record.data);
                    }
                }
            }
        } catch {
            failures++;
        }
    }

    return { records, failures };
}

/** 判读主机名是否为 IP 字面量（能被规范化为 IP） */
function isIPLiteralHost(hostname) {
    if (hostname.includes(':')) return true;
    if (!/^[0-9a-fA-F.x]+$/.test(hostname)) return false;
    return normalizeIPv4(hostname) !== null;
}

/**
 * 出网请求的统一校验入口：字面量校验 + 可选 DoH 解析校验。
 * 任何由用户输入驱动的出网请求（采集站搜索/详情、代理转发）都必须先过这一关。
 *
 * @param {string} urlString 待校验的目标 URL
 * @param {object} [opts]
 * @param {boolean} [opts.doh] 是否启用 DoH 解析校验（默认取模块开关）
 * @param {boolean} [opts.dohStrict] DoH 查询全部失败时是否拦截（默认宽松放行，避免可用性受损）
 * @returns {Promise<{ok: boolean, reason?: string}>}
 */
export async function checkUpstreamAllowed(urlString, opts = {}) {
    if (!isValidProxyUrl(urlString)) {
        return { ok: false, reason: '目标地址不在允许范围内（仅支持公网 http/https）' };
    }

    const doh = opts.doh ?? dohEnabled;
    if (!doh) return { ok: true };

    let hostname;
    try {
        const parsed = new URL(urlString);
        hostname = parsed.hostname;
        if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
    } catch {
        return { ok: false, reason: '无效的目标地址' };
    }

    // IP 字面量已在 isValidProxyUrl 完成校验，这里只处理域名
    if (!hostname.includes(':') && !isIPLiteralHost(hostname)) {
        const cached = DOH_CACHE.get(hostname);
        if (cached && Date.now() - cached.t < DOH_TTL) {
            if (cached.blocked) return { ok: false, reason: '目标地址解析到私有/保留网络' };
            return { ok: true };
        }

        const { records, failures } = await resolveViaDoh(hostname);
        const blocked = records.some((ip) => isPrivateIP(ip));
        DOH_CACHE.set(hostname, { t: Date.now(), blocked });

        if (failures === 2) {
            // A/AAAA 查询全部失败：严格模式拦截，宽松模式放行（记录日志）
            if (opts.dohStrict) {
                return { ok: false, reason: 'DNS 解析失败且已开启严格模式，已拦截请求' };
            }
            console.warn(`[ssrf] DoH 解析失败（${hostname}），按宽松模式放行`);
            return { ok: true };
        }

        if (blocked) {
            return { ok: false, reason: '目标地址解析到私有/保留网络' };
        }
    }

    return { ok: true };
}