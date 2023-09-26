from app import db
from sqlalchemy import ForeignKey

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean,default=False,nullable=False)

class Pais(db.Model):
    __tablename__ = 'pais'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)

    def __str__(self):
        return self.nombre

class Provincia(db.Model):
    __tablename__ = 'provincia'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    pais = db.Column(
        db.Integer,
        ForeignKey('pais.id'),
        nullable=False
    )
    pais_obj = db.relationship('Pais')

    def __str__(self):
        return self.nombre
    
class Localidad(db.Model):
    __tablename__ = 'localidad'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    provincia = db.Column(
        db.Integer,
        ForeignKey('provincia.id'),
        nullable=False
    )
    provincia_obj = db.relationship('Provincia')

    def __str__(self):
        return self.nombre
    
class Persona(db.Model):
    __tablename__ = 'persona'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    nacimiento = db.Column(db.Date, nullable=False)
    activo = db.Column(db.Boolean, nullable=False)
    telefono = db.Column(db.Integer, nullable=True)

    localidad = db.Column(
        db.Integer,
        ForeignKey('localidad.id'),
        nullable=False
    )

    def __str__(self):
        return f"{self.nombre} - {self.apellido}"
