#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ConfigParser
import datetime
import hashlib
import json
import logging
import os
import uuid
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from abc import ABCMeta, abstractmethod
from optparse import OptionParser

import scoring
import validators

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    __slots__ = ('type', 'required', 'nullable', 'max_length', 'min_length', 'empty_values')
    __metaclass__ = ABCMeta

    def __init__(self, type=None, required=False, nullable=False, max_length=None, min_length=None):
        self.type = type
        self.required, self.nullable = required, nullable
        self.max_length, self.min_length = max_length, min_length
        self.empty_values = [None, '']

    def pre_validate(self, name, value):
        if self.required and value in self.empty_values:
            raise ValueError('{} must be required'.format(name))

        if not self.nullable and value in self.empty_values:
            raise ValueError('{} must be not null'.format(name))

        if self.max_length and value:
            validators.MaxLengthValidator(self.max_length).validate(value)

        if self.min_length and value:
            validators.MinLengthValidator(self.min_length).validate(value)

        if self.type and value:
            if not isinstance(value, self.type):
                raise TypeError("{} must be a {}".format(name, self.type))

    @abstractmethod
    def validate(self, value):
        pass


class CharField(Field):
    def __init__(self, *args, **kwargs):
        super(CharField, self).__init__(*args, **kwargs)
        self.type = unicode
        self.validator = None

    def validate(self, value):
        pass


class EmailField(CharField):
    def __init__(self, *args, **kwargs):
        super(EmailField, self).__init__(*args, **kwargs)
        self.type = unicode

    def validate(self, value):
        if value:
            validators.EmailValidator().validate(value)


class PhoneField(CharField):
    def __init__(self, *args, **kwargs):
        super(PhoneField, self).__init__(*args, **kwargs)
        self.max_length = self.min_length = 11

    def validate(self, value):
        if value:
            validators.MaxLengthValidator(self.max_length).validate(value)
            validators.MinLengthValidator(self.min_length).validate(value)
            validators.PhoneValidator().validate(value)


class DateField(CharField):
    def __init__(self, *args, **kwargs):
        super(DateField, self).__init__(*args, **kwargs)
        self.type = unicode

    def validate(self, value):
        if value:
            validators.DateValidator().validate(value)


class BirthDayField(DateField):
    def __init__(self, *args, **kwargs):
        super(BirthDayField, self).__init__(*args, **kwargs)
        self.type = unicode

    def validate(self, value):
        if value:
            validators.BirthDayValidator().validate(value)


class GenderField(Field):
    def __init__(self, *args, **kwargs):
        super(GenderField, self).__init__(*args, **kwargs)
        self.type = int

    def validate(self, value):
        if value:
            validators.GenderValidator().validate(value)


class ClientIDsField(Field):
    def __init__(self, *args, **kwargs):
        super(ClientIDsField, self).__init__(*args, **kwargs)
        self.type = list

    def validate(self, value):
        if len(value) == 0:
            raise ValueError('ClientIDs are empty')
        validators.ClientIDsValidator().validate(value)


class ArgumentsField(Field):
    def __init__(self, *args, **kwargs):
        super(ArgumentsField, self).__init__(*args, **kwargs)

    def validate(self, value):
        if value:
            if isinstance(value, OnlineScoreRequest):
                validators.OnlineScoreRequestValidator().validate(value)


class Request(object):

    def __init__(self, *args, **kwargs):
        pass

    def __setattr__(self, key, value):
        self.__getattribute__(key).pre_validate(key, value)
        self.__getattribute__(key).validate(value)
        setattr(self.__class__, key, value)

    def get_context(self):
        return [field for field, value in self.__dict__.items() if field]


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, first_name=None, last_name=None, email=None, phone=None, birthday=None, gender=None):
        super(OnlineScoreRequest, self).__init__(self)
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

    def get_context(self):
        return {'has': [field for field, value in self.__class__.__dict__.items() if value]}


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, client_ids=None, date=None):
        super(ClientsInterestsRequest, self).__init__()
        self.client_ids = client_ids
        self.date = date

    def get_context(self):
        return {'nclients': len(self.client_ids)}


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, account=None, login=None, token=None, arguments=None, method=None):
        super(MethodRequest, self).__init__()
        self.account = account
        self.login = login
        self.token = token
        self.method = method
        self.arguments = arguments

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def get_context(self):
        self.arguments.get_context()


def check_auth(request):
    if request.login == ADMIN_LOGIN:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


# обработчик метода online_score

def online_score_request_builder(**data):
    return OnlineScoreRequest(**data)


def online_score_handler(request, store):
    if check_auth(request):
        score = 42
        if not request.is_admin:
            score = scoring.get_score(store=store,
                                      phone=request.arguments.phone,
                                      email=request.arguments.email,
                                      birthday=request.arguments.birthday,
                                      gender=request.arguments.gender,
                                      first_name=request.arguments.first_name,
                                      last_name=request.arguments.last_name)

        response, code = {"score": score}, OK
    else:
        response, code = "Forbidden", FORBIDDEN
    return response, code


# Обработчик метода clients_interests
def clients_interests_request_builder(**data):
    return ClientsInterestsRequest(**data)


def clients_interests_handler(request, store):
    if check_auth(request):
        interests = {}
        for cid in request.arguments.client_ids:
            interests[cid] = scoring.get_interests(store=store, cid=cid)
        response, code = interests, OK
    else:
        response, code = "Forbidden", FORBIDDEN
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    estimator = {
        "online_score": {"request_builder": online_score_request_builder, "handler": online_score_handler},
        "clients_interests": {"request_builder": clients_interests_request_builder, "handler": clients_interests_handler}
    }

    store = None
    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        data = None
        try:
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        except Exception as error:
            logging.error(error.message)
            code = BAD_REQUEST
        if data:
            path = self.path.strip("/")
            logging.info("{}: {} {}".format(self.path, data, context["request_id"]))
            try:
                if data.get('arguments'):
                    print(OnlineScoreRequest.first_name)
                    d1 = OnlineScoreRequest(first_name="sdsd", last_name="sdsd", email='ccc@dd.com', "12.12.2012", )
                    print(OnlineScoreRequest.first_name)
                    print(d1.first_name)

                    d2 = OnlineScoreRequest(**data['arguments'])
                    d3 = OnlineScoreRequest(**data['arguments'])
                    #data['arguments'] = self.estimator[path]['request_builder'](**data['arguments'])
                    response, code = self.estimator[path]['handler'](MethodRequest(**data), self.store)
                    del data
                else:
                    raise ValueError('Arguments are emty')
            except Exception as e:
                logging.exception("Unexpected error: %s" % e)
                code = INTERNAL_ERROR
        else:
            code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


def is_file(file_path):
    return True if file_path and os.path.isfile(file_path) else False


def parse_config(config_path):
    conf = ConfigParser.RawConfigParser(allow_no_value=True)
    conf.read(config_path)
    return dict((name.upper(), value) for (name, value) in conf.items('default'))


config = {
    "LOGGING_FILE": "./log/log-{}.log".format(datetime.date.today().strftime('%Y.%m.%d')),
}

if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-c", "--config", action="store", default=None)
    (opts, args) = op.parse_args()

    if is_file(opts.config):
        config.update(parse_config(opts.config))

    logging.basicConfig(format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        filename=config.get('LOGGING_FILE'),
                        filemode='a',
                        level=logging.INFO)

    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at http://localhost:{}".format(opts.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
