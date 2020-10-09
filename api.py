from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# UTILS
from utils import mapping

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
CORS(app)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot access this function'})

    users = User.query.all()
    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['password'] = user.password
        result.append(user_data)

    return jsonify({'users': result})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user_by_id(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot access this function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    user_data['password'] = user.password

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot access this function'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'], password=hashed_password, admin=False)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot access this function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True

    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot access this function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login', methods=['POST'])
def login():
    app.config['SECRET_KEY'] = 'thisissecret'
    # auth = request.authorization
    auth = request.get_json()

    if not auth or not auth['username'] or not auth['password']:
        return make_response('Could not verify', 401, {'WWW-Authenticate':  'Basic realm = "Login required! "'})

    user = User.query.filter_by(name=auth['username']).first()

    if not user:
        return jsonify({'message': 'Could not verify!'}), 401
        # return make_response('Could not verify', 401, {'WWW-Authenticate':  'Basic realm = "Login required! "'})

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        mapped_user = mapping.map_user(user)
        mapped_user['token'] = token.decode('UTF-8')
        return jsonify({'info': mapped_user})

    return make_response('Could not verify', 401, {'WWW-Authenticate':  'Basic realm = "Login required! "'})


@app.route('/logout', methods=['POST'])
def logout():
    app.config['SECRET_KEY'] = 'invalid'

    return jsonify({'message': 'logged out'})


# TODO
@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):

    todos = Todo.query.filter_by(user_id=current_user.id).all()
    result = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        result.append(todo_data)

    return jsonify({'todos': result})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_todo_by_id(current_user, todo_id):

    selected_todo = Todo.query.filter_by(
        id=todo_id, user_id=current_user.id).first()

    if not selected_todo:
        return jsonify({'message': 'There is no todo with this id!'})

    result = []
    todo_mapped = {}
    todo_mapped['id'] = selected_todo.id
    todo_mapped['text'] = selected_todo.text
    todo_mapped['complete'] = selected_todo.complete
    result.append(todo_mapped)
    return jsonify({'todos': result})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):

    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)

    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo created!'})


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    selected_todo = Todo.query.filter_by(
        id=todo_id, user_id=current_user.id).first()
    if not selected_todo:
        return jsonify({'message': 'No todo found'})

    db.session.delete(selected_todo)
    db.session.commit()

    return jsonify({'message': 'Todo deleted successfully!'})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    selected_todo = Todo.query.filter_by(
        id=todo_id, user_id=current_user.id).first()

    if not selected_todo:
        return jsonify({'message': 'No todo found!'})

    selected_todo.complete = True
    db.session.commit()
    return jsonify({'message': 'Todo set as complete!'})

# PAUSED ON 40:54 https://www.youtube.com/watch?v=WxGBoY5iNXY


if __name__ == '__main__':
    app.run(debug=True)
