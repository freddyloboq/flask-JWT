import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from models import db, User
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///mibasededatos.db'
app.config["JWT_SECRET_KEY"] = os.getenv('LLAVE_SECRETA_JWT')
app.config["SECRET_KEY"] = os.getenv("LLAVE_SECRETA")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=3)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

expire = timedelta(minutes=1)

@app.route('/', methods=['GET'])
def home():
  return jsonify({"message": "Hello, World!"})

@app.route("/getUSer", methods=['GET'])
def get_user():
  usuarios = User.query.all()
  usuarios_serializados = list(map(lambda usuario: usuario.serialize(), usuarios))

  return jsonify({
    "status": "success",
    "data": usuarios_serializados
  }), 200

@app.route("/getUserById/<int:id>", methods=['GET'])
@jwt_required()
def get_user_by_id(id):
  usuario = User.query.filter_by(id=id).first()
  return ({
    "status": "success",
    "data": usuario.serialize()
  }), 200

@app.route('/createUser', methods=['POST'])
def create():
  data = request.json
  usuario = User()

  password_hash = bcrypt.generate_password_hash(data['password'])

  print(data['nombre'])
  usuario.nombre = data['nombre']
  usuario.apellido = data['apellido']
  usuario.email = data['email']
  usuario.password = password_hash

  # print(usuario)
  db.session.add(usuario)
  db.session.commit()


@app.route('/login', methods=['POST'])
def login():
  data = request.json
  usuario_existente = User.query.filter_by(email = data['email']).first()

  #Si el usuario existe
  if usuario_existente is not None:
    if bcrypt.check_password_hash(usuario_existente.password, data['password']):
      token = create_access_token(identity=usuario_existente.serialize(), expires_delta= expire)

      return jsonify({"token": token, "message": "Login exitoso"}), 200
    else:
      return jsonify({"message": "usuario o contraseña incorrecta"}), 401
  else:
    return jsonify({"message": "usuario o contraseña incorrecta"}), 401


if __name__ == "__main__":
  app.run(host='localhost', port=5002, debug=True)