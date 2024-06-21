from flask import Flask, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'my_secret_key'

users = {
    'admin': {'password': 'admin123'},
    'user1': {'password': 'password1'},
    'user2': {'password': 'password2'}
}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            return 'Неверные учетные данные. <a href="/login">Попробовать снова</a>'

    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@app.route('/profile')
def profile():
    if 'username' in session:
        return f'Профиль пользователя: {session["username"]}. <a href="/logout">Выйти</a>'
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5000, debug=True)
