import datetime
import hashlib
import random
import unittest

import api


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {'request_id': str(random.randint(1000, 1000000))}
        self.headers = {'Content-Type': 'application/json'}
        self.store = None

    def get_token(self, login, account):
        if login == api.ADMIN_LOGIN:
            return hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).hexdigest().decode()
        else:
            return hashlib.sha512(account + login + api.SALT).hexdigest().decode()

    def test_should_return_ok_code_on_requests_with_correct_params(self):
        account = u"client_account"
        login = u"client_login"
        method = u"online_score"

        arguments = {
            "phone": u"79999990000",
            "email": u"client_name@otus.ru",
            "first_name": u"Firstname",
            "last_name": u"Lastname",
            "birthday": u"01.01.1999",
            "gender": 1
        }

        request = {
            "account": account,
            "login": login,
            "method": method,
            "token": self.get_token(login, account),
            "arguments": arguments
        }
        _, code = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.OK, code)

        arguments = {
            "client_ids": [2, 3],
            "date": u"02.01.2017"
        }
        request['arguments'] = arguments
        request['method'] = u'clients_interests'
        _, code = api.clients_interests_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.OK, code)

    def test_should_return_invalid_request_code_on_requests_with_nullable_params(self):
        account = u"client_account"
        login = u"client_login"
        method = None
        arguments = {
            "phone": u"79999990000",
            "email": u"client_name@otus.ru",
            "first_name": u"Firstname",
            "last_name": u"Lastname",
            "birthday": u"01.01.1999",
            "gender": 1
        }
        request = {
            "account": account,
            "login": login,
            "method": method,
            "token": self.get_token(login, account),
            "arguments": arguments
        }
        _, code = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.INVALID_REQUEST, code)

        request['arguments'] = None
        _, code = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.INVALID_REQUEST, code)

    def test_should_return_ok_code_on_request_with_null_params(self):
        account = None
        login = api.ADMIN_LOGIN.decode()
        arguments = {
            "phone": u"79999990000",
            "email": u"client_name@otus.ru",
            "first_name": u"Firstname",
            "last_name": u"Lastname",
            "birthday": u"01.01.1999",
            "gender": 1
        }

        request = {
            "account": account,
            "login": login,
            "method": u'online_score',
            "token": self.get_token(login, account),
            "arguments": arguments
        }

        _, code = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.OK, code)

    def test_should_return_invalid_request_code_on_online_score_request_with_incorrect_arguments(self):
        account = u"client_account"
        login = u"client_login"
        method = u"online_score"

        arguments = {
            "phone": u"89999990000",
            "email": u"client_name#otus.ru",
            "first_name": u"Firstname",
            "last_name": u"Lastname",
            "birthday": u"1.01.1999",
            "gender": 4
        }

        request = {
            "account": account,
            "login": login,
            "method": method,
            "token": self.get_token(login, account),
            "arguments": arguments
        }

        _, code = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.INVALID_REQUEST, code)

    def test_should_return_admin_score_on_online_score_request_with_admin_login(self):
        account = u"admin"
        login = api.ADMIN_LOGIN.decode()
        arguments = {
            "phone": u"79999990000",
            "email": u"client_name@otus.ru",
            "first_name": u"Firstname",
            "last_name": u"Lastname",
            "birthday": u"01.01.1999",
            "gender": 1
        }

        request = {
            "account": account,
            "login": login,
            "method": u'online_score',
            "token": self.get_token(login, account),
            "arguments": arguments
        }
        resp, _ = api.online_score_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(resp['score'], 42)

    def test_should_return_invalid_request_code_on_clients_interests_request_with_incorrect_arguments(self):
        login = u'client_login'
        account = u'client_account'

        arguments = {
            "client_ids": [u'1', u'2', u'3', 4, 5],
            "date": u"2.01.2017"
        }
        request = {
            "account": account,
            "login": login,
            "method": u'clients_interests',
            "token": self.get_token(login, account),
            "arguments": arguments
        }
        _, code = api.clients_interests_handler({"body": request, "headers": self.headers}, self.context, self.store)
        self.assertEquals(api.INVALID_REQUEST, code)



if __name__ == "__main__":
    unittest.main()
