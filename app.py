from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/check_headers', methods=['POST'])
def check_headers():
    url = request.json.get('url')
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    results = {}
    try:
        verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']
        verb_results = []
        for verb in verbs:
            try:
                req = requests.request(verb, url)
                verb_result = {'verb': verb, 'status_code': req.status_code, 'reason': req.reason}
                if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
                    verb_result['vulnerability'] = 'Possible Cross Site Tracing vulnerability found'
                verb_results.append(verb_result)
            except requests.RequestException as e:
                verb_results.append({'verb': verb, 'error': str(e)})

        results['verbs'] = verb_results

        headers_to_check = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']
        header_results = {}
        req1 = requests.get(url)
        for header in headers_to_check:
            result = req1.headers.get(header, 'Not found')
            header_results[header] = result
        results['headers'] = header_results

        cookie_results = []
        for cookie in req1.cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value,
                'secure': 'True' if cookie.secure else 'False',
                'httponly': 'True' if 'httponly' in cookie._rest.keys() else 'False',
                'domain_initial_dot': 'True' if cookie.domain_initial_dot else 'False'
            }
            cookie_results.append(cookie_info)
        results['cookies'] = cookie_results

        security_headers = {
            'X-XSS-Protection': ('X-XSS-Protection not set properly, XSS may be possible', '1; mode=block'),
            'X-Content-Type-Options': ('X-Content-Type-Options not set properly', 'nosniff'),
            'Strict-Transport-Security': ('HSTS header not set, MITM attacks may be possible', None),
            'Content-Security-Policy': ('Content-Security-Policy missing', None)
        }
        security_results = {}
        for header, (message, expected_value) in security_headers.items():
            value = req1.headers.get(header)
            if value is None or (expected_value and value != expected_value):
                security_results[header] = message
            else:
                security_results[header] = f'{header} set properly: {value}'
        results['security'] = security_results

    except requests.RequestException as e:
        return jsonify({'error': f"Request failed: {e}"}), 500

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
