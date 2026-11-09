from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ast
import json
import re

HOST = "127.0.0.1"
PORT = 8765
MAX_SIZE = 256 * 1024


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

        # Détection de fonctions potentiellement dangereuses
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

        # Détection de secrets écrits directement dans le code
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
                if (
                    secret_pattern.search(target)
                    and text.lower() not in placeholders
                ):
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


class Server(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if path not in ("/", "/index.html"):
            self.send_error(404)
            return

        try:
            page = Path(__file__).with_name("index.html").read_bytes()
        except OSError:
            self.send_error(500, "index.html introuvable")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_SIZE:
                self.send_json({"error": "Fichier vide ou trop volumineux."}, 413)
                return

            payload = json.loads(self.rfile.read(length))
            source = payload.get("code")

            if not isinstance(source, str):
                self.send_json({"error": "Code invalide."}, 400)
                return

            self.send_json(analyze(source))

        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Requête invalide."}, 400)

    def log_message(self, format, *args):
        print("[VULNIX]", format % args)


if __name__ == "__main__":
    print("================================")
    print("       VULNIX 0.1")
    print("================================")
    print(f"Interface : http://{HOST}:{PORT}")
    print("Serveur accessible uniquement sur ce PC.")
    print("Arrêt : Ctrl+C")

    server = ThreadingHTTPServer((HOST, PORT), Server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt de VULNIX.")
    finally:
        server.server_close()
