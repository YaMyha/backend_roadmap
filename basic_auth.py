from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "user1": "password1",
    "user2": "password2"
}


@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username
    return None


@app.route('/protected')
@auth.login_required
def protected():
    return jsonify(message=f"Hello, {auth.current_user()}!")


if __name__ == '__main__':
    app.run(debug=True)
