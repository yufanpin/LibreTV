import { sha256 } from '../js/sha256.js';

// 在所有响应上附加的安全响应头
const SECURITY_HEADERS = {
    // 宽松 CSP：兼容零构建架构下的内联脚本(初始化/环境变量注入)与 ArtPlayer/HLS.js
    // 关键仍在于 object-src 'none' / frame-ancestors / base-uri 等子指令
    'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https: http:",
        "media-src 'self' blob: https: http:",
        "connect-src 'self' https: http:",
        "font-src 'self' data: https:",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'self'",
        "form-action 'self'",
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

export async function onRequest(context) {
  const { request, env, next } = context;
  const response = await next();

  // 复制响应头并附加安全头（不修改上游响应对象）
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value);
    }
  }

  const contentType = headers.get("content-type") || "";
  
  if (contentType.includes("text/html")) {
    let html = await response.text();
    
    // 处理普通密码
    const password = env.PASSWORD || "";
    let passwordHash = "";
    if (password) {
      passwordHash = await sha256(password);
    }
    html = html.replace('window.__ENV__.PASSWORD = "{{PASSWORD}}";', 
      `window.__ENV__.PASSWORD = "${passwordHash}";`);

    // 移除 ADMINPASSWORD 占位符
    html = html.replace('window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";',
      'window.__ENV__.ADMINPASSWORD = "";');
    
    return new Response(html, {
      headers,
      status: response.status,
      statusText: response.statusText,
    });
  }
  
  // 非 HTML 响应：透传 body 并附带安全头
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}