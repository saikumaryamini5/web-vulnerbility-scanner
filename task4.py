from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Allow Netlify to access the backend
CORS(app,
     resources={r"/*": {"origins": "*"}},
     supports_credentials=False)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'https://webscannerr.netlify.app'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


# ------------------------- Vulnerability Scanner -------------------------
class WebVulnScanner:
    def __init__(self):
        self.results = []

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        self.sqli_payloads = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--"
        ]

        self.remediations = {
            'XSS': {
                'type': 'XSS',
                'description': 'Cross-Site Scripting',
                'severity': 'High'
            },
            'SQL Injection': {
                'type': 'SQL Injection',
                'description': 'Database Injection',
                'severity': 'Critical'
            },
            'Security Header Missing': {
                'type': 'Security Header Missing',
                'description': 'Important security header missing',
                'severity': 'Medium'
            }
        }

    def test_xss(self, url, param, endpoint):
        for payload in self.xss_payloads:
            test_url = f"{url}{endpoint}?{param}={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if payload in resp.text:
                    return True, payload
            except:
                pass
        return False, None

    def test_sqli(self, url, param, endpoint):
        for payload in self.sqli_payloads:
            test_url = f"{url}{endpoint}?{param}={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if "error" in resp.text.lower() or resp.status_code >= 500:
                    return True, payload
            except:
                pass
        return False, None

    def test_headers(self, full_url):
        required = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
        issues = []
        try:
            r = requests.get(full_url, timeout=5)
            for h in required:
                if h not in r.headers:
                    issues.append(f"Missing {h}")
        except:
            pass
        return issues

    def scan_endpoint(self, base_url, endpoint):
        result = {'endpoint': endpoint, 'vulnerabilities': [], 'risk_score': 0}

        for param in ['q', 'search', 'id', 'name']:
            ok, payload = self.test_xss(base_url, param, endpoint)
            if ok:
                v = self.remediations['XSS'].copy()
                v['payload'] = payload
                result['vulnerabilities'].append(v)
                result['risk_score'] += 8

        for param in ['id', 'user', 'page']:
            ok, payload = self.test_sqli(base_url, param, endpoint)
            if ok:
                v = self.remediations['SQL Injection'].copy()
                v['payload'] = payload
                result['vulnerabilities'].append(v)
                result['risk_score'] += 10

        issues = self.test_headers(base_url + endpoint)
        for i in issues:
            v = self.remediations['Security Header Missing'].copy()
            v['details'] = i
            result['vulnerabilities'].append(v)
            result['risk_score'] += 4

        return result


scanner = WebVulnScanner()


@app.route("/")
def home():
    return "Backend running successfully!"


@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():
    # Handle preflight
    if request.method == "OPTIONS":
        return "", 200

    data = request.json
    target_url = data["url"]
    endpoints = data.get("endpoints", ["/", "/login", "/search", "/admin", "/api/users"])

    scanner.results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scanner.scan_endpoint, target_url, ep) for ep in endpoints]
        for f in futures:
            res = f.result()
            if res["vulnerabilities"]:
                scanner.results.append(res)

    response = {
        "results": scanner.results,
        "total_vulns": sum(len(r["vulnerabilities"]) for r in scanner.results),
        "risk_score": sum(r["risk_score"] for r in scanner.results)
    }

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
