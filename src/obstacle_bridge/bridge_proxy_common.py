from __future__ import annotations

import base64
import contextlib
import ctypes
import logging
import os
import socket
import sys
import urllib.parse
import urllib.request
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple


ProxyEndpoint = Tuple[str, int]


def strip_host_brackets(host: str) -> str:
    text = str(host or "").strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def format_connect_authority(host: str, port: int) -> str:
    host_s = strip_host_brackets(str(host or "")).strip()
    if ":" in host_s and not host_s.startswith("["):
        host_s = f"[{host_s}]"
    return f"{host_s}:{int(port)}"


def parse_proxy_authority(value: str, default_port: int = 8080) -> Optional[ProxyEndpoint]:
    text = str(value or "").strip()
    if not text:
        return None
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].strip()
    if not text:
        return None
    host = text
    port = int(default_port)
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif text.count(":") == 1:
        base, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            host = base
            port = int(maybe_port)
    return (strip_host_brackets(host), int(port)) if host else None


def parse_proxy_spec(spec: str, secure: bool = False) -> Optional[ProxyEndpoint]:
    preferred = ("https", "wss") if secure else ("http", "ws")
    fallback = None
    for raw_item in str(spec or "").split(";"):
        item = raw_item.strip()
        if not item:
            continue
        if "=" not in item:
            parsed = parse_proxy_authority(item)
            if parsed:
                fallback = parsed
            continue
        scheme, value = item.split("=", 1)
        scheme = scheme.strip().lower()
        parsed = parse_proxy_authority(value)
        if not parsed:
            continue
        if scheme in preferred:
            return parsed
        if fallback is None:
            fallback = parsed
    return fallback


def env_get_proxy_for_target(
    target_host: str,
    *,
    secure: bool = False,
    log: Optional[logging.Logger] = None,
    log_prefix: str = "[PROXY]",
) -> Optional[ProxyEndpoint]:
    host = strip_host_brackets(str(target_host or "")).strip()
    if not host:
        return None
    if urllib.request.proxy_bypass(host):
        if log:
            log.debug("%s env bypass matched host=%s", log_prefix, host)
        return None
    proxies = urllib.request.getproxies()
    proxy_url = proxies.get("https" if secure else "http")
    if not proxy_url:
        if log:
            log.debug("%s env mode found no %s proxy", log_prefix, "HTTPS_PROXY" if secure else "HTTP_PROXY")
        return None
    parsed = urllib.parse.urlsplit(proxy_url)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https", "ws", "wss"):
        raise RuntimeError(f"unsupported proxy scheme in environment: {parsed.scheme}")
    if parsed.hostname:
        return strip_host_brackets(parsed.hostname), int(parsed.port or 8080)
    return parse_proxy_authority(proxy_url)


def test_system_proxy_override(
    *,
    secure: bool = False,
    log: Optional[logging.Logger] = None,
    log_prefix: str = "[PROXY]",
) -> Optional[ProxyEndpoint]:
    spec = str(os.environ.get("OBSTACLEBRIDGE_TEST_SYSTEM_PROXY", "") or "").strip()
    if not spec:
        return None
    parsed = parse_proxy_spec(spec, secure=secure)
    if parsed is None:
        raise RuntimeError("invalid OBSTACLEBRIDGE_TEST_SYSTEM_PROXY value")
    if log:
        log.debug("%s using test system proxy override endpoint=%s:%d", log_prefix, parsed[0], int(parsed[1]))
    return parsed


def win_get_proxy_for_url(
    url: str,
    *,
    secure: bool = False,
    log: Optional[logging.Logger] = None,
    log_prefix: str = "[PROXY]",
) -> Optional[ProxyEndpoint]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
    HINTERNET = ctypes.c_void_p

    winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = wintypes.BOOL
    winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [ctypes.c_void_p]
    winhttp.WinHttpOpen.restype = HINTERNET
    winhttp.WinHttpOpen.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    winhttp.WinHttpGetProxyForUrl.restype = wintypes.BOOL
    winhttp.WinHttpGetProxyForUrl.argtypes = [
        HINTERNET,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
    winhttp.WinHttpCloseHandle.argtypes = [HINTERNET]

    class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
        _fields_ = [
            ("fAutoDetect", wintypes.BOOL),
            ("lpszAutoConfigUrl", ctypes.c_void_p),
            ("lpszProxy", ctypes.c_void_p),
            ("lpszProxyBypass", ctypes.c_void_p),
        ]

    class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
        _fields_ = [
            ("dwFlags", wintypes.DWORD),
            ("dwAutoDetectFlags", wintypes.DWORD),
            ("lpszAutoConfigUrl", wintypes.LPCWSTR),
            ("lpvReserved", wintypes.LPVOID),
            ("dwReserved", wintypes.DWORD),
            ("fAutoLogonIfChallenged", wintypes.BOOL),
        ]

    class WINHTTP_PROXY_INFO(ctypes.Structure):
        _fields_ = [
            ("dwAccessType", wintypes.DWORD),
            ("lpszProxy", ctypes.c_void_p),
            ("lpszProxyBypass", ctypes.c_void_p),
        ]

    WINHTTP_ACCESS_TYPE_NO_PROXY = 1
    WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
    WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
    WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002
    WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
    WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

    def _wide(ptr: int) -> str:
        return ctypes.wstring_at(ptr) if ptr else ""

    def _free(ptr: int) -> None:
        if ptr:
            kernel32.GlobalFree(ctypes.c_void_p(ptr))

    manual_proxy = ""
    auto_url = ""
    auto_detect = True
    ie_cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    try:
        if bool(winhttp.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(ie_cfg))):
            auto_detect = bool(ie_cfg.fAutoDetect)
            manual_proxy = _wide(ie_cfg.lpszProxy)
            auto_url = _wide(ie_cfg.lpszAutoConfigUrl)
            if log:
                log.debug(
                    "%s IE proxy config auto_detect=%s auto_config_url=%r manual_proxy=%r",
                    log_prefix,
                    auto_detect,
                    auto_url,
                    manual_proxy,
                )
        elif log:
            log.debug("%s WinHttpGetIEProxyConfigForCurrentUser failed last_error=%s", log_prefix, ctypes.get_last_error())
        parsed = parse_proxy_spec(manual_proxy, secure=secure)
        if parsed:
            if log:
                log.debug("%s using manual IE proxy endpoint=%s:%d", log_prefix, parsed[0], int(parsed[1]))
            return parsed
    finally:
        _free(getattr(ie_cfg, "lpszAutoConfigUrl", 0))
        _free(getattr(ie_cfg, "lpszProxy", 0))
        _free(getattr(ie_cfg, "lpszProxyBypass", 0))

    session = winhttp.WinHttpOpen("ObstacleBridge/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, None, None, 0)
    if not session:
        raise RuntimeError(f"WinHttpOpen failed: {ctypes.get_last_error()}")
    try:
        opts = WINHTTP_AUTOPROXY_OPTIONS()
        if auto_url:
            opts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
            opts.lpszAutoConfigUrl = auto_url
            if log:
                log.debug("%s WinHTTP auto-proxy using PAC url=%r for %s", log_prefix, auto_url, url)
        else:
            opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
            opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
            if log:
                log.debug("%s WinHTTP auto-proxy using auto_detect=%s flags=DHCP|DNS_A for %s", log_prefix, auto_detect, url)
        opts.fAutoLogonIfChallenged = True
        info = WINHTTP_PROXY_INFO()
        if not bool(winhttp.WinHttpGetProxyForUrl(session, str(url), ctypes.byref(opts), ctypes.byref(info))):
            if log:
                log.debug("%s WinHttpGetProxyForUrl returned no proxy last_error=%s url=%s", log_prefix, ctypes.get_last_error(), url)
            return None
        try:
            raw_proxy = _wide(info.lpszProxy)
            if log:
                log.debug("%s WinHttpGetProxyForUrl access_type=%s raw_proxy=%r", log_prefix, int(info.dwAccessType), raw_proxy)
            if int(info.dwAccessType) != WINHTTP_ACCESS_TYPE_NAMED_PROXY:
                if log:
                    log.debug("%s WinHTTP access type is not named proxy", log_prefix)
                return None
            parsed = parse_proxy_spec(raw_proxy, secure=secure)
            if log:
                log.debug("%s parsed WinHTTP proxy endpoint=%r", log_prefix, parsed)
            return parsed
        finally:
            _free(getattr(info, "lpszProxy", 0))
            _free(getattr(info, "lpszProxyBypass", 0))
    finally:
        winhttp.WinHttpCloseHandle(session)


def resolve_proxy_endpoint(
    *,
    mode: str,
    target_host: str,
    target_port: int,
    secure: bool = False,
    manual_host: str = "",
    manual_port: int = 0,
    feature_enabled: bool = True,
    platform: Optional[str] = None,
    log: Optional[logging.Logger] = None,
    log_prefix: str = "[PROXY]",
) -> Optional[ProxyEndpoint]:
    normalized_mode = str(mode or "off").strip().lower()
    platform_name = sys.platform if platform is None else platform
    if log:
        log.debug(
            "%s endpoint lookup target=%s mode=%s peer_configured=%s platform=%s tls=%s",
            log_prefix,
            format_connect_authority(target_host, target_port),
            normalized_mode,
            bool(feature_enabled),
            platform_name,
            secure,
        )
    if not feature_enabled or normalized_mode == "off":
        if log:
            log.debug("%s proxy feature disabled", log_prefix)
        return None
    if normalized_mode == "env":
        endpoint = env_get_proxy_for_target(target_host, secure=secure, log=log, log_prefix=log_prefix)
        if endpoint is None:
            if log:
                log.debug("%s env proxy lookup returned no endpoint", log_prefix)
            return None
        if log:
            log.debug("%s env proxy selected endpoint=%s:%d", log_prefix, endpoint[0], int(endpoint[1]))
        return endpoint
    if normalized_mode == "manual":
        host = strip_host_brackets(str(manual_host or "")).strip()
        port = int(manual_port or 0)
        if not host or port <= 0:
            if log:
                log.debug("%s manual mode missing host/port host=%r port=%s", log_prefix, host, port)
            raise RuntimeError("manual proxy mode requires proxy host and port")
        if log:
            log.debug("%s manual proxy selected endpoint=%s:%d", log_prefix, host, port)
        return host, port
    if normalized_mode == "system":
        test_override = test_system_proxy_override(secure=secure, log=log, log_prefix=log_prefix)
        if test_override is not None:
            return test_override
        if platform_name != "win32":
            if log:
                log.debug("%s rejecting proxy lookup on unsupported platform=%s", log_prefix, platform_name)
            raise RuntimeError("system proxy support is currently available on Windows only")
        lookup_url = f"{'https' if secure else 'http'}://{format_connect_authority(target_host, target_port)}"
        if log:
            log.debug("%s system proxy lookup url=%s secure=%s", log_prefix, lookup_url, secure)
        endpoint = win_get_proxy_for_url(lookup_url, secure=secure, log=log, log_prefix=log_prefix)
        if endpoint is None:
            if log:
                log.debug("%s system proxy lookup returned no endpoint", log_prefix)
            return None
        if log:
            log.debug("%s system proxy selected endpoint=%s:%d", log_prefix, endpoint[0], int(endpoint[1]))
        return endpoint
    if log:
        log.debug("%s unsupported mode=%s", log_prefix, normalized_mode)
    raise RuntimeError(f"unsupported proxy mode: {normalized_mode}")


def build_windows_negotiate_spn(host: str) -> str:
    host_s = strip_host_brackets(str(host or "")).strip()
    if not host_s:
        raise RuntimeError("empty proxy host for Negotiate target name")
    upper = host_s.upper()
    if "." in upper:
        parts = upper.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else upper
        return f"HTTP/{host_s}@{domain}"
    return f"HTTP/{host_s}"


def build_proxy_connect_request(
    target_host: str,
    target_port: int,
    *,
    auth_header: Optional[str] = None,
    user_agent: str = "ObstacleBridge-proxy/1.0",
) -> bytes:
    authority = format_connect_authority(target_host, target_port)
    lines = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Connection: keep-alive",
        "Proxy-Connection: keep-alive",
        f"User-Agent: {user_agent}",
    ]
    if auth_header:
        lines.append(f"Proxy-Authorization: {auth_header}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def win_build_negotiate_token(target_name: str, challenge: Optional[bytes] = None) -> str:
    secur32 = ctypes.WinDLL("secur32", use_last_error=True)

    class CredHandle(ctypes.Structure):
        _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

    class CtxtHandle(ctypes.Structure):
        _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]

    class TimeStamp(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.DWORD)]

    class SecBuffer(ctypes.Structure):
        _fields_ = [
            ("cbBuffer", wintypes.ULONG),
            ("BufferType", wintypes.ULONG),
            ("pvBuffer", ctypes.c_void_p),
        ]

    class SecBufferDesc(ctypes.Structure):
        _fields_ = [
            ("ulVersion", wintypes.ULONG),
            ("cBuffers", wintypes.ULONG),
            ("pBuffers", ctypes.POINTER(SecBuffer)),
        ]

    SECPKG_CRED_OUTBOUND = 2
    SECURITY_NATIVE_DREP = 0x00000010
    ISC_REQ_CONFIDENTIALITY = 0x00000010
    SECBUFFER_VERSION = 0
    SECBUFFER_TOKEN = 2
    SEC_E_OK = 0x00000000
    SEC_I_CONTINUE_NEEDED = 0x00090312

    expiry = TimeStamp()
    cred = CredHandle()
    status = secur32.AcquireCredentialsHandleW(
        None,
        "Negotiate",
        SECPKG_CRED_OUTBOUND,
        None,
        None,
        None,
        None,
        ctypes.byref(cred),
        ctypes.byref(expiry),
    )
    if int(status) != SEC_E_OK:
        raise RuntimeError(f"AcquireCredentialsHandleW failed: 0x{int(status) & 0xFFFFFFFF:08x}")

    ctx = CtxtHandle()
    attrs = wintypes.ULONG()
    out_buf_raw = ctypes.create_string_buffer(65536)
    out_buf = SecBuffer(len(out_buf_raw), SECBUFFER_TOKEN, ctypes.cast(out_buf_raw, ctypes.c_void_p))
    out_desc = SecBufferDesc(SECBUFFER_VERSION, 1, ctypes.pointer(out_buf))

    _ignored_challenge = challenge
    in_desc_ptr = None

    try:
        status = secur32.InitializeSecurityContextW(
            ctypes.byref(cred),
            None,
            ctypes.c_wchar_p(target_name),
            ISC_REQ_CONFIDENTIALITY,
            0,
            SECURITY_NATIVE_DREP,
            in_desc_ptr,
            0,
            ctypes.byref(ctx),
            ctypes.byref(out_desc),
            ctypes.byref(attrs),
            ctypes.byref(expiry),
        )
        if int(status) not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED):
            raise RuntimeError(f"InitializeSecurityContextW failed: 0x{int(status) & 0xFFFFFFFF:08x}")
        if int(out_buf.cbBuffer) <= 0:
            raise RuntimeError("InitializeSecurityContextW returned no token")
        return base64.b64encode(out_buf_raw.raw[: int(out_buf.cbBuffer)]).decode("ascii")
    finally:
        with contextlib.suppress(Exception):
            if ctx.dwLower or ctx.dwUpper:
                secur32.DeleteSecurityContext(ctypes.byref(ctx))
        with contextlib.suppress(Exception):
            secur32.FreeCredentialsHandle(ctypes.byref(cred))


def read_http_proxy_response(sock: socket.socket) -> Tuple[int, Dict[str, List[str]]]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            raise RuntimeError("proxy response headers too large")
    header_blob, _, _rest = data.partition(b"\r\n\r\n")
    lines = header_blob.decode("iso-8859-1", "replace").split("\r\n")
    if not lines or len(lines[0].split(" ")) < 2:
        raise RuntimeError("invalid proxy response")
    parts = lines[0].split(" ", 2)
    status_code = int(parts[1]) if parts[1].isdigit() else 0
    headers: Dict[str, List[str]] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.setdefault(key.strip().lower(), []).append(value.strip())
    return status_code, headers


def open_http_connect_tunnel(
    *,
    target_host: str,
    target_port: int,
    proxy: ProxyEndpoint,
    auth_mode: str = "none",
    timeout: float = 5.0,
    log: Optional[logging.Logger] = None,
    log_prefix: str = "[PROXY]",
    user_agent: str = "ObstacleBridge-proxy/1.0",
) -> socket.socket:
    proxy_host, proxy_port = proxy
    normalized_auth = str(auth_mode or "none").strip().lower()
    challenge_blob = None
    attempts = 0
    if log:
        log.debug(
            "%s opening proxy tunnel target=%s via=%s:%d auth=%s",
            log_prefix,
            format_connect_authority(target_host, target_port),
            proxy_host,
            int(proxy_port),
            normalized_auth,
        )
    while attempts < 3:
        attempts += 1
        if log:
            log.debug("%s CONNECT attempt=%d proxy=%s:%d", log_prefix, attempts, proxy_host, int(proxy_port))
        sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
        try:
            auth_header = None
            if normalized_auth == "negotiate" and attempts > 1:
                if log:
                    log.debug("%s building Negotiate token challenge_present=%s", log_prefix, challenge_blob is not None)
                auth_header = "Negotiate " + win_build_negotiate_token(
                    build_windows_negotiate_spn(proxy_host),
                    challenge=challenge_blob,
                )
            request = build_proxy_connect_request(
                target_host,
                target_port,
                auth_header=auth_header,
                user_agent=user_agent,
            )
            sock.sendall(request)
            status_code, headers = read_http_proxy_response(sock)
            if log:
                log.debug("%s CONNECT response status=%s proxy_authenticate=%s", log_prefix, status_code, headers.get("proxy-authenticate", []))
            if status_code == 200:
                if log:
                    log.debug("%s CONNECT tunnel established on attempt=%d", log_prefix, attempts)
                sock.setblocking(False)
                return sock
            if status_code != 407:
                raise RuntimeError(f"proxy CONNECT failed with HTTP {status_code}")
            if normalized_auth != "negotiate":
                raise RuntimeError("proxy requires authentication but proxy auth mode is not negotiate")
            negotiate_headers = [value for value in headers.get("proxy-authenticate", []) if value.lower().startswith("negotiate")]
            if not negotiate_headers:
                raise RuntimeError("proxy does not offer Negotiate authentication")
            challenge_blob = None
            token = negotiate_headers[0][len("Negotiate") :].strip()
            if token:
                if log:
                    log.debug("%s proxy supplied Negotiate challenge token", log_prefix)
                challenge_blob = base64.b64decode(token)
            elif log:
                log.debug("%s proxy requested Negotiate without challenge token", log_prefix)
        except Exception:
            sock.close()
            raise
        sock.close()
    raise RuntimeError("proxy authentication failed after multiple attempts")
