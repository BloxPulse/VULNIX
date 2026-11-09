from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from collections import deque
import ast
import json
import os
import re
import secrets
import threading
import time

PORT = int(os.environ.get("PORT", "8765"))
HOST = os.environ.get("HOST", "0.0.0.0" if "PORT" in os.environ else "127.0.0.1")
MAX_SIZE = 256 * 1024
MAX_ISSUES = 200
SOCKET_TIMEOUT = 10
BODY_DEADLINE = 15
MAX_CONNECTIONS = 16
RATE_LIMIT_PER_IP = 20
RATE_LIMIT_GLOBAL = 120
RATE_WINDOW = 60
PROXY_HOPS = int(os.environ.get("PROXY_HOPS", "0"))


def get_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def get_targets(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names = []
        for item in node.elts:
            names.extend(get_targets(item))
        return names
    return []


def analyze(source):
    issues = []

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        issues.append({
            "severity": "error",
            "category": "Syntaxe",
            "title": "Erreur de syntaxe",
            "detail": exc.msg,
            "suggestion": "Corrige cette erreur avant de poursuivre.",
            "line": exc.lineno or 1,
            "column": exc.offset or 1
        })
        return {
            "score": 0,
            "issues": issues,
            "valid_syntax": False
        }

    secret_pattern = re.compile(
        r"password|passwd|secret|api[_-]?key|access[_-]?token",
        re.IGNORECASE
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = get_name(node.func)

            if name in ("eval", "exec"):
                issues.append({
                    "severity": "high",
                    "category": "Sécurité",
                    "title": f"Utilisation de {name}()",
                    "detail": "Cette fonction peut interpréter une chaîne comme du code.",
                    "suggestion": "Évite cette fonction sur des données non fiables.",
                    "line": node.lineno,
                    "column": node.col_offset + 1
                })

            elif name == "os.system":
                issues.append({
                    "severity": "medium",
                    "category": "Sécurité",
                    "title": "Commande système directe",
                    "detail": "os.system() peut présenter un risque si des données externes sont utilisées.",
                    "suggestion": "Privilégie subprocess avec une liste d'arguments et sans shell=True.",
                    "line": node.lineno,
                    "column": node.col_offset + 1
                })

            elif name == "pickle.loads":
                issues.append({
                    "severity": "high",
                    "category": "Sécurité",
                    "title": "Désérialisation pickle",
                    "detail": "Un fichier pickle non fiable peut permettre l'exécution de code.",
                    "suggestion": "N'utilise pas pickle.loads() avec des données non fiables.",
                    "line": node.lineno,
                    "column": node.col_offset + 1
                })

            elif name in (
                "subprocess.run",
                "subprocess.call",
                "subprocess.Popen"
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        issues.append({
                            "severity": "high",
                            "category": "Sécurité",
                            "title": "subprocess avec shell=True",
                            "detail": "Cette option peut créer un risque d'injection de commandes.",
                            "suggestion": "Utilise shell=False et passe les arguments dans une liste.",
                            "line": node.lineno,
                            "column": node.col_offset + 1
                        })

        if isinstance(node, ast.Assign):
            targets = []
            for target in node.targets:
                targets.extend(get_targets(target))
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = get_targets(node.target)
            value = node.value
        else:
            continue

        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text = value.value.strip()
            placeholders = {
                "", "changeme", "change_me", "your_api_key",
                "placeholder", "example", "xxx"
            }

            for target in targets:
                if secret_pattern.search(target) and text.lower() not in placeholders:
                    issues.append({
                        "severity": "medium",
                        "category": "Sécurité",
                        "title": "Secret potentiellement codé en dur",
                        "detail": "Une valeur sensible semble être directement écrite dans le code. Sa valeur n'est pas affichée.",
                        "suggestion": "Utilise une variable d'environnement ou un gestionnaire de secrets.",
                        "line": node.lineno,
                        "column": node.col_offset + 1
                    })

    weights = {
        "high": 20,
        "medium": 10,
        "low": 3
    }

    score = max(
        0,
        100 - sum(weights.get(issue["severity"], 0) for issue in issues)
    )

    return {
        "score": score,
        "issues": issues,
        "valid_syntax": True
    }


class RateLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.per_ip = {}
        self.global_hits = deque()

    def allow(self, ip):
        now = time.monotonic()
        limit_time = now - RATE_WINDOW

        with self.lock:
            while self.global_hits and self.global_hits[0] < limit_time:
                self.global_hits.popleft()

            if len(self.global_hits) >= RATE_LIMIT_GLOBAL:
                return False

            hits = self.per_ip.setdefault(ip, deque())
            while hits and hits[0] < limit_time:
                hits.popleft()

            if len(hits) >= RATE_LIMIT_PER_IP:
                return False

            hits.append(now)
            self.global_hits.append(now)

            if len(self.per_ip) > 5000:
                for key in [k for k, v in self.per_ip.items() if not v or v[-1] < limit_time]:
                    del self.per_ip[key]

            return True


limiter = RateLimiter()


class LimitedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Retry-After: 5\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return

        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Server(BaseHTTPRequestHandler):
    timeout = SOCKET_TIMEOUT

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")

        if self.headers and self.headers.get("X-Forwarded-Proto") == "https":
            self.send_header("Strict-Transport-Security", "max-age=31536000")

        super().end_headers()

    def client_ip(self):
        peer = self.client_address[0]

        if PROXY_HOPS > 0:
            parts = [
                part.strip()
                for part in self.headers.get("X-Forwarded-For", "").split(",")
                if part.strip()
            ]
            if len(parts) >= PROXY_HOPS:
                return parts[-PROXY_HOPS][:64]

        return peer

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self, length):
        deadline = time.monotonic() + BODY_DEADLINE
        chunks = []
        remaining = length

        while remaining > 0:
            if time.monotonic() > deadline:
                raise TimeoutError("corps trop lent")

            chunk = self.rfile.read(min(remaining, 16384))
            if not chunk:
                raise ValueError("corps incomplet")

            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if path not in ("/", "/index.html"):
            self.send_error(404)
            return

        try:
            page = Path(__file__).with_name("index.html").read_bytes()
        except OSError:
            self.send_error(500, "index.html introuvable")
            return

        nonce = secrets.token_urlsafe(16)
        page = page.replace(b"<script>", f'<script nonce="{nonce}">'.encode())
        page = page.replace(b"<style>", f'<style nonce="{nonce}">'.encode())

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            f"script-src 'nonce-{nonce}'; "
            f"style-src 'nonce-{nonce}'; "
            "connect-src 'self'; img-src 'self' data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_error(404)
            return

        try:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                self.send_json({"error": "Type de contenu non pris en charge."}, 415)
                return

            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_SIZE:
                self.send_json({"error": "Fichier vide ou trop volumineux."}, 413)
                return

            if not limiter.allow(self.client_ip()):
                body = json.dumps({
                    "error": "Trop de requêtes. Réessaie dans un instant."
                }).encode("utf-8")
                self.send_response(429)
                self.send_header("Retry-After", "30")
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            payload = json.loads(self.read_body(length))
            if not isinstance(payload, dict):
                self.send_json({"error": "Requête invalide."}, 400)
                return

            source = payload.get("code")
            if not isinstance(source, str):
                self.send_json({"error": "Code invalide."}, 400)
                return

            result = analyze(source)
            total = len(result["issues"])

            if total > MAX_ISSUES:
                result["issues"] = result["issues"][:MAX_ISSUES]
                result["truncated"] = True

            result["total_issues"] = total
            self.send_json(result)

        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Requête invalide."}, 400)
        except (RecursionError, MemoryError):
            self.send_json({"error": "Code trop complexe à analyser."}, 422)
        except (TimeoutError, OSError):
            self.close_connection = True
        except Exception as exc:
            print("[VULNIX] erreur interne :", type(exc).__name__)
            try:
                self.send_json({"error": "Erreur interne."}, 500)
            except OSError:
                pass

    def log_message(self, format, *args):
        message = re.sub(r"[\x00-\x1f\x7f]", "?", format % args)[:200]
        print("[VULNIX]", message)


if __name__ == "__main__":
    print("================================")
    print("       VULNIX 0.1")
    print("================================")
    print(f"Interface : http://{HOST}:{PORT}")

    if HOST in ("127.0.0.1", "localhost"):
        print("Serveur accessible uniquement sur ce PC.")
    else:
        print("Serveur accessible depuis le réseau.")

    print("Arrêt : Ctrl+C")

    server = LimitedServer((HOST, PORT), Server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt de VULNIX.")
    finally:
        server.server_close()
