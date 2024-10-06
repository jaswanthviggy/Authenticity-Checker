from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests
import hashlib

app = FastAPI()

class PasswordRequest(BaseModel):
    password: str

def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code} check the API')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

@app.post("/check_password")
def check_password(password_request: PasswordRequest):
    password = password_request.password
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]

    response = request_api_data(first5_char)
    count = get_password_leaks_count(response, tail)

    return {"count": count}

@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <html>
        <head>
            <title>Password Leak Checker</title>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    background-color: #121212;
                    color: #fff;
                    text-align: center;
                    padding: 50px;
                    margin: 0;
                    animation: fadeIn 1s ease;
                }
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                .container {
                    background: rgba(30, 30, 30, 0.9);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
                    max-width: 400px;
                    margin: auto;
                    transition: transform 0.3s, box-shadow 0.3s;
                }
                .container:hover {
                    transform: scale(1.05);
                    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7);
                }
                input[type="text"] {
                    width: 100%;
                    padding: 15px;
                    margin: 10px 0;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    background-color: #444;
                    color: #999; /* Light color for placeholder */
                    transition: background-color 0.3s;
                }
                input[type="text"]:focus {
                    background-color: #555;
                    outline: none;
                    color: white; /* Change text color to white on focus */
                }
                button {
                    background: linear-gradient(90deg, #8e44ad, #3498db);
                    color: white;
                    padding: 15px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    transition: background-color 0.3s, transform 0.2s;
                    width: 100%;
                    position: relative;
                    overflow: hidden;
                }
                button:hover {
                    background-color: #2980b9;
                    transform: translateY(-2px);
                }
                button:before {
                    content: '';
                    position: absolute;
                    background: rgba(255, 255, 255, 0.2);
                    height: 100%;
                    width: 100%;
                    top: 0;
                    left: 0;
                    border-radius: 5px;
                    transform: scale(0);
                    transition: transform 0.3s ease;
                    z-index: 0;
                }
                button:hover:before {
                    transform: scale(1);
                }
                #result {
                    margin-top: 20px;
                    font-weight: bold;
                    opacity: 0;
                    transition: opacity 0.5s;
                }
                #result.show {
                    opacity: 1;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Password Leak Checker</h1>
                <input type="text" id="password" placeholder="Enter your password" 
                       onfocus="clearPlaceholder(this)" 
                       onblur="restorePlaceholder(this)">
                <button onclick="checkPassword()">Check Password</button>
                <div id="result"></div>
            </div>
            <script>
                function clearPlaceholder(input) {
                    input.style.color = 'white'; // Change text color to indicate active input
                    input.value = ''; // Clear the input
                }

                function restorePlaceholder(input) {
                    if (input.value === '') {
                        input.style.color = '#999'; // Light color for placeholder
                        input.value = input.placeholder; // Restore placeholder
                    }
                }

                async function checkPassword() {
                    const password = document.getElementById('password').value;
                    const response = await fetch('/.netlify/functions/check_password', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ password: password })
                    });
                    const data = await response.json();
                    const response = await fetch('/.netlify/functions/check_password', {
                    const resultDiv = document.getElementById('result');
                    resultDiv.innerText =
                        data.count ? `${password} was found ${data.count} times` : `${password} was not found`;
                    resultDiv.classList.add('show');
                }
            </script>
        </body>
    </html>
    """
