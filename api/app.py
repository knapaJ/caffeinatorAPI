import dateutil.parser
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import uuid
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil import parser
import jwt
from functools import wraps

# Initialisation
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "..\\data\\db.sqlite")
# Database init
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "5i8cpk3x7IQeUmX16Jtr"
db = SQLAlchemy(app)
mar = Marshmallow(app)


# ORM Classes
class Drink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    machine_id = db.Column(db.Integer, db.ForeignKey('machine.id'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String, unique=True, nullable=False)
    login = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)

    drinks = db.relationship('Drink', backref="user", cascade='all,delete', order_by=Drink.time, lazy=True)

    def __repr__(self):
        return f'User {self.email}; {self.login}:{self.password}'


class Machine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, nullable=False, default="Coffee machine")
    caffeine_mg = db.Column(db.Integer, nullable=False)

    drinks = db.relationship('Drink', backref="machine", order_by=Drink.time, lazy=True)

    def __repr__(self):
        return f'Machine {self.uuid} dispensing at {self.caffeine_mg}mg/cup'


def token_required(f):
    """
    Authentication decorator, returns 401 on failed auth.
    Expects x-access-token header to be present in request.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({
                "error_code": 401,
                "error_text": "Authentication token missing!"
            }), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(uuid=data['uuid']).first()
        except:
            return jsonify({
                "error_code": 401,
                "error_text": "Auth token invalid"
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error_code": 500, "error_text": str(e)}), 500


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error_code": 405, "error_text": "Method not allowed!"}), 405


@app.errorhandler(404)
def endpoint_not_found(e):
    return jsonify({"error_code": 404, "error_text": "Endpoint not found!"}), 404


@app.route('/hello-world', methods=['GET'])
def hello_world():
    return jsonify({'message': 'Hello World'})


@app.route('/user/request', methods=['PUT'])
def add_user():
    """
    Tries to add user, expects json object with 'login', 'email' and 'password'
    :return:
    400 - missing arguments,
    409 - user exists,
    201 - user created
    """
    data = request.get_json()
    if not("login" in data and 'email' in data and 'password' in data):
        return jsonify({
            "error_code": 400,
            "error_text": "Data missing!"
        }), 400

    new_login = data['login']
    new_password = generate_password_hash(data['password'], method='sha256')
    new_email = data['email']
    new_uuid_str = str(uuid.uuid4())

    if User.query.filter_by(login=new_login).first() or User.query.filter_by(email=new_email).first():
        return jsonify({
            "error_code": 409,
            "error_text": "Already exists"
        }), 409

    user = User(login=new_login, password=new_password, email=new_email, uuid=new_uuid_str)

    db.session.add(user)
    db.session.commit()
    return jsonify({
        "id": user.uuid
    }), 201


@app.route('/machine', methods=['POST'])
def add_machine():
    """
    Tries to add machine. Expects json object with 'name' and 'caffeine'.
    :return:
    400 - missing arguments,
    201 - machine crated
    """
    data = request.get_json()
    if not ("name" in data and "caffeine" in data):
        return jsonify({
            "error_code": 400,
            "error_text": "Argumetns missing"
        }), 400

    new_name = data['name']
    new_caffeine_mg = data['caffeine']
    new_uuid_str = str(uuid.uuid4())

    new_machine = Machine(name=new_name, caffeine_mg=new_caffeine_mg, uuid=new_uuid_str)

    db.session.add(new_machine)
    db.session.commit()

    return jsonify({
        "id": new_machine.uuid
    }), 201


@app.route('/machines', methods=['GET'])
def get_all_machines():
    machines = Machine.query.all()

    output = []
    for machine in machines:
        machine_data = {
            'name': machine.name,
            'id': machine.uuid,
            'caffeine': machine.caffeine_mg
        }
        output.append(machine_data)

    return jsonify({"machines": output}), 200


@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()

    output = []
    for user in users:
        user_data = {
            'login': user.login,
            'email': user.email,
            'id': user.uuid
        }
        output.append(user_data)

    return jsonify({'users': output}), 200


@app.route('/coffee/buy/<user_id>/<machine_id>', methods=['GET'])
def register_coffee_now(user_id, machine_id):
    user = User.query.filter_by(uuid=user_id).first()
    if not user:
        return jsonify({
            "error_code": 404,
            "error_text": "User not found!"
        }), 404

    machine = Machine.query.filter_by(uuid=machine_id).first()
    if not machine:
        return jsonify({
            "error_code": 404,
            "error_text": "Machine not found"
        }), 404

    new_drink = Drink(time=datetime.datetime.now())

    user.drinks.append(new_drink)
    machine.drinks.append(new_drink)

    db.session.add(user)
    db.session.add(machine)
    db.session.commit()
    return '', 201


@app.route('/coffee/buy/<user_id>/<machine_id>', methods=['PUT'])
def register_coffee_time(user_id, machine_id):
    data = request.get_json()

    if "timestamp" not in data:
        return jsonify({
            "error_code": 400,
            "error_text": "Arguments missing!"
        })
    try:
        new_time = parser.parse(data['timestamp'])
    except dateutil.parser.ParserError:
        return jsonify({
            "error_code": 400,
            "error_text": "Bad timestamp!"
        }), 400

    user = User.query.filter_by(uuid=user_id).first()
    if not user:
        return jsonify({
            "error_code": 404,
            "error_text": "User not found!"
        }), 404

    machine = Machine.query.filter_by(uuid=machine_id).first()
    if not machine:
        return jsonify({
            "error_code": 404,
            "error_text": "Machine not found"
        }), 404

    new_drink = Drink(time=new_time)

    user.drinks.append(new_drink)
    machine.drinks.append(new_drink)

    db.session.add(user)
    db.session.add(machine)
    db.session.commit()
    return '', 201


@app.route('/stats/coffee', methods=['GET'])
def get_global_coffee():
    coffees = Drink.query.all()

    output = []
    for coffee in coffees:
        coffee_data = {
            "time": str(coffee.time),
            "sold_by": coffee.machine.name,
            "sold_by_id": coffee.machine.uuid,
            "caffeine": coffee.machine.caffeine_mg
        }
        output.append(coffee_data)

    return jsonify({"sold_coffee_global": output}), 200


@app.route('/stats/coffee/machine/<machine_id>', methods=['GET'])
def get_coffee_by_machine(machine_id):
    machine = Machine.query.filter_by(uuid=machine_id).first()

    if not machine:
        return jsonify({
            "error_code": 404,
            "error_text": "Machine not found!"
        }), 404

    output = []
    for coffee in machine.drinks:
        coffee_data = {
            "sold_on": coffee.time,
        }
        output.append(coffee_data)

    return jsonify({
        "machine_id": machine.uuid,
        "machine_name": machine.name,
        "caffeine": machine.caffeine_mg,
        "sold_drinks": output
    }), 200


@app.route('/user/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(login=auth.username).first()
    if not user:
        return jsonify({
            "error_code": 404,
            "error_text": "No such user exists!"
        }), 404

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'uuid': user.uuid, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token, "user_id": user.uuid}), 200

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/stats/coffee/user/<user_id>', methods=['GET'])
@token_required
def get_user_stats(current_user, user_id):
    if not current_user.uuid == user_id:
        return jsonify({
            "error_code": 403,
            "error_text": "You dont have access to this user!"
        }), 403

    output = []
    user = User.query.filter_by(uuid=user_id).first()  # For the sake of extensibility (mby admin users etc.)
    if not user:
        return jsonify({
            "error_code": 404,
            "error_text": "User not found!"
        }), 404

    for drink in user.drinks:
        drink_data = {
            "time": drink.time,
            "sold_by": drink.machine.name,
            "sold_by_id": drink.machine.uuid,
            "caffeine": drink.machine.caffeine_mg
        }
        output.append(drink_data)

    return jsonify({
        "user_id": user.uuid,
        "user": user.login,
        "user_email": user.email,
        "drinks_bought": output
    }), 200


# run server
if __name__ == '__main__':
    app.run()
