// functions/proxy/[[path]].js
// ============================================================
// Cloudflare Pages Function: 代理 /proxy/*
// 关键改进（就地优化）：
//   1. SSRF 防护 —— 共享 functions/_lib/ssrf.js，拦截内网/保留网段
//   2. 二进制内容修复 —— 去除 response.text() 损坏，改为流式透传 + Cache API
//   3. M3U8 保留全部清晰度变体 —— 恢复 HLS 自适应码率（ABR）、字幕与音轨
//   4. 修复旧版「重写分片丢失鉴权参数导致 401」—— 重写时注入 ?auth=&t= 参数
//   5. 安全响应头 —— 已由 _middleware.js 处理，此处只需正确返回流
// ============================================================

import { checkUpstreamAllowed, setSsrFfDohEnabled } from '../_lib/ssrf.js';
import { rewriteM3u8, filterAdsFromM3u8 } from '../_lib/m3u8.js';

// --- 环境变量（在 Cloudflare Dashboard > Pages > Settings > 环境变量中设置）---
// CACHE_TTL     代理缓存秒数（默认 86400 = 24 小时）
// DEBUG         设为 'true' 输出调试日志
// USER_AGENTS_JSON  JSON 数组，随机挑选 UA（默认 Chrome 120）
// PASSWORD      鉴权密码（必需，缺失时所有代理请求返回 401）
// SSRF_DOH      设为 '1' 开启 DoH 严格模式，对域名做 DNS-over-HTTPS 解析校验

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// 模块级状态：随每个请求更新（供模块级辅助函数读取）
let DEBUG_ENABLED = false;
let userAgents = [DEFAULT_UA];

export async function onRequest(context) {
    const { request, env, waitUntil } = context;
    const url = new URL(request.url);

    // --- 配置 ---
    DEBUG_ENABLED = env.DEBUG === 'true';
    const CACHE_TTL = parseInt(env.CACHE_TTL || '86400', 10);
    setSsrFfDohEnabled(env.SSRF_DOH === '1');

    userAgents = [DEFAULT_UA];
    try {
        const agentsJson = env.USER_AGENTS_JSON;
        if (agentsJson) {
            const parsed = JSON.parse(agentsJson);
            if (Array.isArray(parsed) && parsed.length > 0) {
                userAgents = parsed;
            } else {
                logDebug('环境变量 USER_AGENTS_JSON 格式无效或为空，使用默认值');
            }
        }
    } catch (e) {
        logDebug(`解析环境变量 USER_AGENTS_JSON 失败: ${e.message}，使用默认值`);
    }

    // --- 鉴权 ---
    if (!(await validateAuth(request, env))) {
        return createJsonResponse({
            success: false,
            error: '代理访问未授权：请检查密码配置或鉴权参数'
        }, 401);
    }

    // --- 提取目标 URL ---
    const targetUrl = getTargetUrlFromPath(url.pathname);
    if (!targetUrl) {
        logDebug(`无效的代理请求路径: ${url.pathname}`);
        return createJsonResponse({ success: false, error: '无效的代理请求。路径应为 /proxy/<经过编码的URL>' }, 400);
    }
    logDebug(`收到代理请求: ${targetUrl}`);

    // --- SSRF 校验（关闭旧版开放代理漏洞）---
    const verdict = await checkUpstreamAllowed(targetUrl);
    if (!verdict.ok) {
        logDebug(`SSRF 拦截: ${targetUrl} — ${verdict.reason}`);
        return createJsonResponse({ success: false, error: `代理目标被拒绝: ${verdict.reason}` }, 403);
    }

    // --- 为 M3U8 重写提供鉴权参数（修复旧版分片 401 问题）---
    const authParams = await buildAuthParams(env);
    const toProxyUrl = (absUrl) => `/proxy/${encodeURIComponent(absUrl)}${authParams}`;

    // --- 缓存层：使用 Cloudflare Cache API（替代旧版 KV 存二进制造成的损坏）---
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: 'GET' });
    let cachedResponse = null;
    try {
        cachedResponse = await cache.match(cacheKey);
    } catch (e) {
        logDebug(`Cache API 读取失败: ${e.message}`);
    }

    let upstreamResponse;
    if (cachedResponse) {
        logDebug(`[缓存命中] ${targetUrl}`);
        upstreamResponse = cachedResponse;
    } else {
        logDebug(`[缓存未命中] ${targetUrl}`);
        try {
            upstreamResponse = await fetchUpstream(targetUrl, request);
        } catch (e) {
            logDebug(`请求上游失败: ${targetUrl} — ${e.message}`);
            return createJsonResponse({ success: false, error: `代理请求失败: ${e.message}` }, 502);
        }
    }

    // --- 判断是否为 M3U8 ---
    const contentType = upstreamResponse.headers.get('Content-Type') || '';
    const isM3u8 = (
        contentType.includes('mpegurl') ||
        contentType.includes('x-mpegurl') ||
        contentType.includes('audio/mpegurl') ||
        targetUrl.toLowerCase().includes('.m3u8')
    );

    // --- M3U8 文本路径：重写（保留全部清晰度 + 字幕 + 音轨）---
    if (isM3u8) {
        const text = await upstreamResponse.text();
        const filtered = filterAdsFromM3u8(text);
        const rewritten = rewriteM3u8(filtered, targetUrl, { toProxyUrl });
        logDebug(`M3U8 重写完成: ${targetUrl}`);
        return createM3u8Response(rewritten);
    }

    // --- 二进制/JSON/其他：流式透传，不做 response.text()（修复旧版损坏问题）---
    if (!cachedResponse && upstreamResponse.ok) {
        // 异步写入 Cache API（不阻塞响应）
        try {
            const cacheHeaders = new Headers(upstreamResponse.headers);
            cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL}`);
            const toCache = new Response(upstreamResponse.clone().body, {
                headers: cacheHeaders
            });
            waitUntil(cache.put(cacheKey, toCache));
            logDebug(`已将二进制响应写入缓存: ${targetUrl}`);
        } catch (e) {
            logDebug(`写入缓存失败 (${targetUrl}): ${e.message}`);
        }
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set('Cache-Control', `public, max-age=${CACHE_TTL}`);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', '*');

    return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: responseHeaders
    });
}

// --- 辅助函数 ---

function logDebug(message) {
    if (DEBUG_ENABLED) {
        console.log(`[Proxy Func] ${message}`);
    }
}

async function validateAuth(request, env) {
    const url = new URL(request.url);
    const authHash = url.searchParams.get('auth');
    const timestamp = url.searchParams.get('t');

    const serverPassword = env.PASSWORD;
    if (!serverPassword) {
        console.error('服务器未设置 PASSWORD 环境变量，代理访问被拒绝');
        return false;
    }

    try {
        const serverPasswordHash = await sha256Hash(serverPassword);
        if (!authHash || authHash !== serverPasswordHash) {
            console.warn('代理请求鉴权失败：密码哈希不匹配');
            return false;
        }
    } catch (error) {
        console.error('计算密码哈希失败:', error);
        return false;
    }

    if (timestamp) {
        const now = Date.now();
        const maxAge = 10 * 60 * 1000; // 10 分钟有效期
        if (now - parseInt(timestamp, 10) > maxAge) {
            console.warn('代理请求鉴权失败：时间戳过期');
            return false;
        }
    }

    return true;
}

function getTargetUrlFromPath(pathname) {
    const encodedUrl = pathname.replace(/^\/proxy\//, '');
    if (!encodedUrl) return null;
    try {
        let decodedUrl = decodeURIComponent(encodedUrl);
        if (!decodedUrl.match(/^https?:\/\//i)) {
            if (encodedUrl.match(/^https?:\/\//i)) {
                decodedUrl = encodedUrl;
                logDebug(`Warning: Path was not encoded but looks like URL: ${decodedUrl}`);
            } else {
                logDebug(`无效的目标URL格式 (解码后): ${decodedUrl}`);
                return null;
            }
        }
        return decodedUrl;
    } catch (e) {
        logDebug(`解码目标URL时出错: ${encodedUrl} - ${e.message}`);
        return null;
    }
}

async function buildAuthParams(env) {
    const serverPassword = env.PASSWORD;
    if (!serverPassword) return '';
    const hash = await sha256Hash(serverPassword);
    return `?auth=${hash}&t=${Date.now()}`;
}

async function sha256Hash(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

async function fetchUpstream(targetUrl, request) {
    const headers = new Headers({
        'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
        'Accept': '*/*',
        'Accept-Language': request.headers.get('Accept-Language') || 'zh-CN,zh;q=0.9,en;q=0.8',
        'Referer': request.headers.get('Referer') || (() => { try { return new URL(targetUrl).origin; } catch { return ''; } })()
    });

    const response = await fetch(targetUrl, { headers, redirect: 'follow' });

    if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        logDebug(`请求失败: ${response.status} ${response.statusText} — ${targetUrl}`);
        throw new Error(`HTTP ${response.status}: ${response.statusText}. URL: ${targetUrl}. Body: ${errorBody.substring(0, 150)}`);
    }

    return response;
}

function createJsonResponse(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*'
        }
    });
}

function createM3u8Response(content) {
    return new Response(content, {
        status: 200,
        headers: {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Cache-Control': 'no-store', // 重写结果内嵌的 auth/t 有 10 分钟有效期，禁止长缓存
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*'
        }
    });
}

// 处理 OPTIONS 预检请求
export async function onOptions(context) {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Max-Age': '86400'
        }
    });
}