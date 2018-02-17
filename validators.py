import datetime
import re


class MaxLengthValidator(object):
    message = "{} len is grater than {}"

    def __init__(self, limit_value):
        self.limit_value = limit_value

    def validate(self, value):
        if len(value) > self.limit_value:
            raise ValueError(self.message.format(value, self.limit_value))


class MinLengthValidator(object):
    message = "{} len is less than {}"

    def __init__(self, limit_value):
        self.limit_value = limit_value

    def validate(self, value):
        if len(value) < self.limit_value:
            raise ValueError(self.message.format(value, self.limit_value))


class EmailValidator(object):
    message = '{} is incorrect email address'
    regex = re.compile(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')

    def validate(self, value):
        if not value or '@' not in value:
            raise ValueError(self.message.format(value))

        if self.regex.match(value) is None:
            raise ValueError(self.message.format(value))


class PhoneValidator(object):
    message = '{} is incorrect phone number'
    regex = re.compile(r'^7[0-9]{10}$')

    def validate(self, value):
        if not isinstance(value, int) and not isinstance(value, unicode):
            raise ValueError(self.message.format(type(value)))

        if isinstance(value, unicode):
            if self.regex.match(value) is None:
                raise ValueError(self.message.format(value))

        if isinstance(value, int):
            if self.regex.match(str(value)) is None:
                raise ValueError(self.message.format(value))


class DateValidator(object):
    message = '{} is incorrect date'
    regex = re.compile(r'^[0-9]{2}[.-/]?[0-9]{2}[.-/]?[0-9]{4}$')

    def validate(self, value):
        if self.regex.match(value) is None:
            raise ValueError(self.message.format(value))


class BirthDayValidator(DateValidator):
    message = '{} is incorrect birth day date'
    date_format = '%d.%m.%Y'

    def validate(self, value):
        if self.regex.match(value) is None:
            raise ValueError(self.message.format(value))
        try:
            date = datetime.datetime.strptime(value, self.date_format)

            if ((date - datetime.datetime.now()).days / 365.25) > 70:
                raise ValueError("{} > 70".format((date - datetime.datetime.now()).year))

        except Exception as error:
            raise ValueError(self.message.format(error))


class GenderValidator(object):
    message = '{} is incorrect gender value'
    control_values = [0, 1, 2]

    def validate(self, value):
        if value not in self.control_values:
            raise ValueError(self.message.format(value, self.control_values))


class OnlineScoreRequestValidator(object):
    message = '{} are incorrect arguments'
    control_fields = [('phone', 'email'), ('first_name', 'last_name'), ('gender', 'birthday')]

    def validate(self, value):
        count = 0
        for (f1, f2) in self.control_fields:
            if getattr(value, f1, None) and getattr(value, f2, None):
                count += 1

        if count == 0:
            raise ValueError(self.message.format(value))


class ClientIDsValidator(object):
    message = 'ClientIDs must be a {}'

    def validate(self, value):
        for id in value:
            if not isinstance(id, int):
                raise ValueError(self.message.format(int))


