from app import ma
from marshmallow import fields

class UserBasicSchema(ma.Schema):
    username = fields.String()

class UserAdminSchema(UserBasicSchema):
    id = fields.Integer(dump_only=True)
    password_hash = fields.String()
    hi_username = fields.Method('get_username')

    def get_username(self,object):
        return "hi " + object.username

class CountryBasicSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()


class ProvinceBasicSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()
    pais = fields.Integer()
    pais_obj = fields.Nested(CountryBasicSchema)

class LocalidadBasicSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()
    province = fields.Integer()
    provincia_obj = fields.Nested(ProvinceBasicSchema)