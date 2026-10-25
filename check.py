"""Проверка фильтра alice-gateway: запрещённое — пустой 403, разрешённое доходит до HA.

--offline: собирает образ в Docker на этом компьютере, вместо HA подставляет заглушку и
           проверяет белый список, обходы путей, окно привязки, extra_paths и адрес для HA.
--url https://<поддомен>: те же запросы снаружи через роутер (запускает пользователь).
Только стандартная библиотека Python. Выход 0 — всё сошлось, 1 — есть расхождения.
"""
import argparse
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
APP = HERE / "alice_gateway"
IMAGE = "alice-gateway-check"
PUBLIC = "gw.example.test"

# (метод, путь, лишние заголовки). Каждый обязан получить пустой 403.
FORBIDDEN = [
    ("GET", "/", {}),
    ("GET", "/api/", {}),
    ("GET", "/api/states", {}),
    ("GET", "/api/websocket", {"Upgrade": "websocket", "Connection": "Upgrade"}),
    ("GET", "/api/yandex_smart_home/v1.0/ping", {"Upgrade": "websocket", "Connection": "Upgrade"}),
    ("GET", "/auth/authorize?response_type=code", {}),
    ("GET", "/auth/providers", {}),
    ("POST", "/auth/login_flow", {}),
    ("GET", "/manifest.json", {}),
    ("GET", "/frontend_latest/app.js", {}),
    ("GET", "/local/x.txt", {}),
    ("GET", "/api/hassio/info", {}),
    ("POST", "/api/webhook/abc", {}),
    ("POST", "/Auth/Token", {}),
    ("POST", "/api/webhook/TEST.HOOK", {}),
    ("POST", "/api/webhook/testxhook", {}),
    # обходы (сверка 5.1 п. 7)
    ("GET", "/api/yandex_smart_home/v1.0/../../states", {}),
    ("GET", "/api/yandex_smart_home/v1.0/%2e%2e/%2e%2e/states", {}),
    ("GET", "/api/yandex_smart_home/v1.0/ping/..", {}),
    ("GET", "/api/yandex_smart_home/v1.0%2Fping", {}),
    ("GET", "/api/yandex_smart_home%2fv1.0/ping", {}),
    ("GET", "//api/yandex_smart_home/v1.0/ping", {}),
    ("GET", "/api//yandex_smart_home/v1.0/ping", {}),
    ("GET", "/api/yandex_smart_home/v1.0/ping/", {}),
    ("GET", "/api/yandex_smart_home/v1.0/ping;x=1", {}),
    ("GET", "/api/yandex_smart_home/v1.0/./ping", {}),
    ("GET", "/api\\yandex_smart_home\\v1.0\\ping", {}),
    ("GET", "/API/yandex_smart_home/v1.0/ping", {}),
    ("GET", "/api/Yandex_Smart_Home/v1.0/ping", {}),
    ("HEAD", "/API/yandex_smart_home/v1.0", {}),
    ("POST", "/API/yandex_smart_home/v1.0/user/devices/action", {}),
    ("GET", "http://127.0.0.1/api/states", {}),
    ("GET", "/api/yandex_smart_home/v1.0/ping?x=1", {}),
    ("POST", "/auth/token?x=1", {}),
    ("GET", "/auth/token", {}),
    ("PUT", "/auth/token", {}),
    ("OPTIONS", "/auth/token", {}),
    ("TRACE", "/api/yandex_smart_home/v1.0/ping", {}),
    ("POST", "/api/yandex_smart_home/v1.0/ping", {}),
    ("GET", "/api/yandex_smart_home/v1.0/user/devices/query", {}),
    ("GET", "/api/yandex_smart_home/v1.0/user/devices/../../../states", {}),
]
# Эти запросы до фильтра не доходят: роутер дома отвечает 400/405, облако Netcraze — своей страницей 404
# (проверка 2026-10-25, журнал фильтра пуст).
ROUTER_REFUSES = {("GET", "http://127.0.0.1/api/states"), ("TRACE", "/api/yandex_smart_home/v1.0/ping")}

# (метод, путь). Должны дойти до HA.
ALLOWED = [
    ("HEAD", "/api/yandex_smart_home/v1.0"),
    ("GET", "/api/yandex_smart_home/v1.0"),
    ("GET", "/api/yandex_smart_home/v1.0/ping"),
    ("GET", "/api/yandex_smart_home/v1.0/user/devices"),
    ("POST", "/api/yandex_smart_home/v1.0/user/devices/query"),
    ("POST", "/api/yandex_smart_home/v1.0/user/devices/action"),
    ("POST", "/api/yandex_smart_home/v1.0/user/unlink"),
    ("POST", "/auth/token"),
]
WINDOW = [
    ("GET", "/auth/authorize?response_type=code&client_id=https%3A%2F%2Fsocial.yandex.net%2F"),
    ("GET", "/auth/providers"),
    ("POST", "/auth/login_flow"),
    ("POST", "/auth/login_flow/0123456789abcdef0123456789abcdef"),
    ("GET", "/frontend_latest/app.abc123.js"),
    ("GET", "/manifest.json"),
    ("GET", "/static/translations/page-authorize/ru-d03e6fdbf696e7a50b163153cd489d73.json"),
    ("GET", "/static/translations/page-authorize/zh-Hans-0123456789abcdef0123456789abcdef.json"),
]
WINDOW_STILL_FORBIDDEN = [
    ("GET", "/static/translations/page-authorize/ru.json"),
    ("GET", "/static/translations/page-onboarding/ru-d03e6fdbf696e7a50b163153cd489d73.json"),
    ("GET", "/static/translations/ru-d03e6fdbf696e7a50b163153cd489d73.json"),
    ("GET", "/"),
    ("GET", "/api/states"),
    ("POST", "/auth/login_flow/../../api/states"),
    ("GET", "/frontend_latest/../api/states"),
    ("GET", "/frontend_latest/%2e%2e/api/states"),
]

# Опция extra_paths для проверки — строки «путь методы», как их передаёт run.sh.
EXTRA_PATHS = "/api/webhook/test.hook POST\n/api/custom/* GET,HEAD\n"

# Заглушка HA: отвечает 200 и эхом того, что получила.
FAKE_HA = """
    server {
        listen 127.0.0.1:80;
        location / {
            return 200 "HA m=$request_method uri=$request_uri host=$host xff=$http_x_forwarded_for xfp=$http_x_forwarded_proto xri=$http_x_real_ip up=$http_upgrade";
        }
    }
"""


def raw_request(host, port, method, target, headers, tls_name=None, timeout=10):
    """Отправить строку запроса как есть, без нормализации пути. Вернуть (код, тело)."""
    lines = [f"{method} {target} HTTP/1.1", f"Host: {tls_name or PUBLIC}", "Connection: close"]
    if method in ("POST", "PUT"):
        headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}
        body = b"grant_type=refresh_token&refresh_token=bad"
        lines.append(f"Content-Length: {len(body)}")
    else:
        body = b""
    lines += [f"{k}: {v}" for k, v in headers.items()]
    data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls_name:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=tls_name)
    with sock:
        sock.sendall(data)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    resp = b"".join(chunks)
    head, _, rest = resp.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
    if b"transfer-encoding: chunked" in head.lower():
        rest = dechunk(rest)
    return status, rest.decode("utf-8", "replace")


def dechunk(data):
    out = b""
    while data:
        size_line, _, data = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out, data = out + data[:size], data[size + 2:]
    return out


class Report:
    def __init__(self):
        self.bad = 0
        self.total = 0

    def check(self, ok, label):
        self.total += 1
        if not ok:
            self.bad += 1
        print(("ok   " if ok else "FAIL ") + label)


def offline(args):
    rep = Report()
    run(["docker", "build", "-q", "-t", IMAGE, str(APP)])
    work = Path(tempfile.mkdtemp(prefix="agw-check-"))
    gw = run(["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"]).strip()
    conf = (APP / "nginx" / "gateway.conf").read_text(encoding="utf-8")
    conf = conf.replace("@PUBLIC_HOST@", PUBLIC).replace("192.168.1.1", gw)
    conf = conf[: conf.rstrip().rfind("}")] + FAKE_HA + "}\n"
    (work / "nginx.conf").write_text(conf, encoding="utf-8", newline="\n")
    (work / "window.map").write_text("", encoding="utf-8")
    extra = extra_map(EXTRA_PATHS)
    rep.check(extra.returncode == 0, f"extra_map.sh: {extra.stderr.strip() or 'ok'}")
    extra = extra.stdout
    (work / "extra.map").write_text(extra, encoding="utf-8", newline="\n")
    name = f"agw-check-{int(time.time())}"
    run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::8090",
         "-v", f"{work}:/tmp/agw", "--entrypoint", "nginx", IMAGE,
         "-c", "/tmp/agw/nginx.conf", "-g", "daemon off;"])
    try:
        port = int(run(["docker", "port", name, "8090"]).strip().splitlines()[0].rsplit(":", 1)[1])
        wait_port(port)
        router = {"X-Real-IP": "203.0.113.7", "X-Forwarded-Proto": "https"}

        def ask(method, target, extra=None):
            return raw_request("127.0.0.1", port, method, target, {**router, **(extra or {})})

        print("== закрытое окно: запрещённое")
        for method, target, extra in FORBIDDEN:
            st, body = ask(method, target, extra)
            rep.check(st == 403 and body == "", f"{method} {target} -> {st} len={len(body)}")
        print("== разрешённое доходит до HA")
        for method, target in ALLOWED:
            st, body = ask(method, target)
            ok = st == 200 and (method == "HEAD" or f"uri={target} " in body)
            rep.check(ok, f"{method} {target} -> {st}")
        print("== заголовки для HA")
        st, body = ask("GET", "/api/yandex_smart_home/v1.0/ping", {"X-Forwarded-For": "192.168.1.120, 1.2.3.4"})
        rep.check(f"host={PUBLIC} " in body, f"Host = публичное имя: {body}")
        rep.check(" xff=203.0.113.7 " in body, "X-Forwarded-For = адрес клиента, XFF клиента выброшен")
        rep.check(" xfp=https " in body and " xri= " in body, "X-Forwarded-Proto https, X-Real-IP не уходит в HA")
        for private in ("192.168.1.120", "10.1.2.3", "172.20.0.5", "127.0.0.1", "fdfe:fe58:e113::1", "fe80::1", "::1"):
            st, body = ask("GET", "/api/yandex_smart_home/v1.0/ping", {"X-Real-IP": private})
            rep.check(" xff=198.51.100.1 " in body, f"частный {private} -> заглушка")
        print("== схема и источник")
        st, body = ask("GET", "/api/yandex_smart_home/v1.0/ping", {"X-Forwarded-Proto": "http"})
        rep.check(st == 403 and body == "", f"X-Forwarded-Proto http -> {st}")
        st, body = raw_request("127.0.0.1", port, "GET", "/api/yandex_smart_home/v1.0/ping", {"X-Real-IP": "203.0.113.7"})
        rep.check(st == 403, f"без X-Forwarded-Proto -> {st}")
        print("== extra_paths")
        for method, target, want in [
            ("POST", "/api/webhook/test.hook", 200),
            ("POST", "/api/webhook/testxhook", 403),
            ("POST", "/api/webhook/TEST.HOOK", 403),
            ("GET", "/api/webhook/test.hook", 403),
            ("POST", "/api/webhook/otherhook", 403),
            ("GET", "/api/custom/a/b.json", 200),
            ("HEAD", "/api/custom/a", 200),
            ("POST", "/api/custom/a", 403),
            ("GET", "/api/custom/", 403),
            ("GET", "/api/custom/../states", 403),
            ("GET", "/api/customx", 403),
        ]:
            st, body = ask(method, target)
            ok = st == want and (body == "" if want == 403 else method == "HEAD" or f"uri={target} " in body)
            rep.check(ok, f"{method} {target} -> {st}, ждали {want}")
        for bad in ("/api/../x POST\n", "/api/x GETX\n", "/api/x/ POST\n", "api/x POST\n", "/api/x%2f POST\n",
                    "/api/x\n"):
            res = extra_map(bad)
            rep.check(res.returncode != 0 and res.stdout == "", f"extra_paths отклоняет {bad.strip()!r}")
        print("== окно открыто")
        (work / "window.map").write_text((APP / "nginx" / "window.map").read_text(encoding="utf-8"),
                                         encoding="utf-8", newline="\n")
        run(["docker", "exec", name, "nginx", "-s", "reload", "-c", "/tmp/agw/nginx.conf"])
        time.sleep(1.5)
        for method, target in WINDOW:
            st, body = ask(method, target)
            rep.check(st == 200 and f"uri={target} " in body, f"{method} {target} -> {st}")
        for method, target in WINDOW_STILL_FORBIDDEN:
            st, body = ask(method, target)
            rep.check(st == 403 and body == "", f"{method} {target} -> {st}")
        print("== частота входа")
        codes = [ask("POST", "/auth/login_flow")[0] for _ in range(12)]
        rep.check(429 in codes, f"12 подряд POST /auth/login_flow: {codes}")
        print("== окно снова закрыто")
        (work / "window.map").write_text("", encoding="utf-8")
        run(["docker", "exec", name, "nginx", "-s", "reload", "-c", "/tmp/agw/nginx.conf"])
        time.sleep(1.5)
        st, body = ask("GET", WINDOW[0][1])
        rep.check(st == 403 and body == "", f"GET /auth/authorize -> {st}")
        print("== журнал без строки запроса")
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, encoding="utf-8")
        logs = logs.stdout + logs.stderr
        rep.check("client_id" not in logs and "refresh_token" not in logs, "в журнале нет строки запроса и тела")
        rep.check("test.hook" not in logs, "идентификатор вебхука скрыт")
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    return rep


def online(args):
    rep = Report()
    parts = urlsplit(args.url)
    host, port = parts.hostname, parts.port or 443
    # --connect: адрес облака из публичного DNS. Изнутри дома имя ведёт на сам роутер, мимо облака.
    addr = args.connect or host
    print(f"соединение с {addr}:{port}, имя {host}")

    def ask(method, target, extra=None):
        return raw_request(addr, port, method, target, extra or {}, tls_name=host)

    print("== запрещённое")
    for method, target, extra in FORBIDDEN:
        st, body = ask(method, target, extra)
        if (method, target) in ROUTER_REFUSES:
            # Отказ роутера или облака, до фильтра; годится любой отказ без содержимого HA.
            ok = (st in (400, 404, 405) and "Home Assistant" not in body
                  and body.strip() != "404: Not Found" and not body.lstrip().startswith("{"))
        else:
            ok = st == 403 and body == ""
        rep.check(ok, f"{method} {target} -> {st} len={len(body)}")
    print("== доходит до HA")
    # До установки Yandex Smart Home (шаг 3) HA отвечает "404: Not Found" — запрос всё равно дошёл до HA.
    st, body = ask("GET", "/api/yandex_smart_home/v1.0/ping")
    rep.check(st == 200 or (st == 404 and body.startswith("404")),
              f"GET /api/yandex_smart_home/v1.0/ping -> {st} {body[:60]!r}")
    st, body = ask("POST", "/auth/token")
    rep.check(st == 400 and body != "", f"POST /auth/token с мусором -> {st} {body[:60]!r}")
    return rep


def extra_map(text):
    """extra_map.sh из образа; байты, чтобы Windows не добавил 
 к строкам."""
    res = subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "/etc/alice-gateway/extra_map.sh", IMAGE],
                         input=text.encode(), capture_output=True)
    return subprocess.CompletedProcess(res.args, res.returncode, res.stdout.decode(), res.stderr.decode())


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8", **kw).stdout


def wait_port(port):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)
    raise SystemExit("nginx не поднялся")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--offline", action="store_true")
    group.add_argument("--url")
    parser.add_argument("--connect", help="с --url: IP-адрес, к которому подключаться (адрес облака)")
    args = parser.parse_args()
    rep = offline(args) if args.offline else online(args)
    print(f"\n{rep.total - rep.bad}/{rep.total} ok")
    return 1 if rep.bad else 0


if __name__ == "__main__":
    sys.exit(main())
