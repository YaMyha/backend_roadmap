from flask import Flask, jsonify, request
import jwt
import datetime
from functools import wraps
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hehe'

salt = bcrypt.gensalt()
users = {
    'user1': bcrypt.hashpw('password1'.encode('utf-8'), salt),
    'user2': bcrypt.hashpw('password2'.encode('utf-8'), salt)
}


def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Отсутствует токен. Доступ запрещен.'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Истек срок действия токена. Доступ запрещен.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Неверный токен. Доступ запрещен.'}), 401

        return f(data['username'], *args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    auth_data = request.get_json()

    if not auth_data or 'username' not in auth_data or 'password' not in auth_data:
        return jsonify({'message': 'Не удалось проверить данные'}), 401

    username = auth_data['username']
    password = auth_data['password']

    if not users.get(username):
        return jsonify({'message': 'Данного пользователя не существует.'}), 401

    if bcrypt.checkpw(password.encode('utf-8'), users.get(username)):
        token = generate_token(username)
        return jsonify({'token': token})

    return jsonify({'message': 'Неверные учетные данные'}), 401


@app.route('/protected', methods=['GET'])
@token_required
def protected(username):
    return jsonify({'message': 'Доступ разрешен для пользователя {}'.format(username)})


if __name__ == '__main__':
    app.run(debug=True)
