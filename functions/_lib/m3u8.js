// functions/_lib/m3u8.js
// ============================================================
// M3U8 播放列表处理：代理路径重写 + 广告分片过滤
// 纯标准 API（无任何 Node/Worker 专属依赖），
// 同时兼容 Cloudflare Workers/Pages Functions 与 Node.js 18+（ESM）。
//
// 与旧版代理实现的关键差异：
//   1. 保留主列表中的全部清晰度变体（#EXT-X-STREAM-INF）、音轨/字幕组
//      （#EXT-X-MEDIA）、I 帧流（#EXT-X-I-FRAME-STREAM-INF）——
//      不再「只挑最高带宽变体递归」，恢复 HLS 自适应码率（ABR）；
//   2. 重写后的 URI 由调用方通过 toProxyUrl 回调生成，可附加鉴权参数，
//      修复旧版「重写分片丢失鉴权参数导致 401」的问题。
// ============================================================

/**
 * 将相对/绝对 URL 基于 base 解析为绝对 URL；解析失败时原样返回。
 * @param {string} url
 * @param {string} base
 */
export function makeAbsolute(url, base) {
    try {
        return new URL(url, base).href;
    } catch {
        return url;
    }
}

/**
 * 判断播放列表是否为「主列表」（含变体或媒体组引用）。
 * @param {string} content
 */
export function isMasterPlaylist(content) {
    return content.includes('#EXT-X-STREAM-INF') || content.includes('#EXT-X-MEDIA:');
}

/**
 * 将 m3u8 中的全部 URI（分片/变体/密钥/初始化段/媒体组）改写为代理路径。
 *
 * @param {string} content 原始 m3u8 内容
 * @param {string} baseUrl  原始播放列表的 URL（用于解析相对路径）
 * @param {object} [options]
 * @param {function(string): string} [options.toProxyUrl] 将绝对 URL 转代理路径的
 *   回调（默认生成 '/proxy/<encodeURIComponent(url)>'；需要附加鉴权参数时传入自定义实现）
 * @param {number} [options.depth] 递归深度保护（上限 5），超限原样返回
 * @returns {string} 重写后的 m3u8
 */
export function rewriteM3u8(content, baseUrl, options = {}) {
    const depth = options.depth || 0;
    if (depth > 5) return content;

    const toProxyUrl = options.toProxyUrl || ((url) => '/proxy/' + encodeURIComponent(url));
    // 代理路径前缀（用于识别「已是代理路径」的行，避免二次包装）
    const proxyPrefix = options.proxyPrefix || '/proxy/';
    const lines = content.split('\n');
    const out = [];

    for (const rawLine of lines) {
        const line = rawLine.replace(/\r$/, ''); // 兼容 CRLF 行尾

        // 含 URI="..." 属性的标签行：KEY（加密密钥）、MAP（初始化段）、MEDIA（音轨/字幕）、I-FRAME-STREAM-INF
        if (
            line.startsWith('#EXT-X-KEY') ||
            line.startsWith('#EXT-X-MAP') ||
            line.startsWith('#EXT-X-MEDIA') ||
            line.startsWith('#EXT-X-I-FRAME-STREAM-INF')
        ) {
            out.push(line.replace(/URI="([^"]+)"/g, (match, uri) => {
                const proxied = toProxyUrl(makeAbsolute(uri, baseUrl));
                // 已是代理路径则跳过，避免二次包装
                if (proxied === uri) return match;
                return `URI="${proxied}"`;
            }));
            continue;
        }

        // 注释与其他标签行、空行：原样保留
        if (line.startsWith('#') || line.trim() === '') {
            out.push(line);
            continue;
        }

        // 媒体分片或子播放列表 URI（非注释行）；已指向当前代理路径的跳过
        if (line.startsWith(proxyPrefix)) {
            out.push(line);
            continue;
        }
        out.push(toProxyUrl(makeAbsolute(line, baseUrl)));
    }

    return out.join('\n');
}

/**
 * 广告分片过滤：移除所有含 #EXT-X-DISCONTINUITY 的行。
 * 采集站广告的典型特征是 DISCONTINUITY 包裹的短时片段组，
 * 这里与旧版保持一致的保守策略：直接剔除 DISCONTINUITY 标记本身，
 * 避免误伤正常多码流内容。
 *
 * @param {string} m3u8Content
 */
export function filterAdsFromM3u8(m3u8Content) {
    if (!m3u8Content) return '';
    return m3u8Content
        .split('\n')
        .filter((line) => !line.includes('#EXT-X-DISCONTINUITY'))
        .join('\n');
}