import string
import idc


class Service(object):
    def __init__(self):
        self.services = {}

    def provider(self, name):
        def wrapped(func):
            self.register(name, func)
            return func
        return wrapped

    def register(self, name, func):
        if name in self.services:
            raise ServiceAlreadyRegistered(name)
        if not is_valid_service_name(name):
            raise ServiceNameIsNotValid(name)
        self.services[name] = func

    def request(self, service, output):
        if service not in self.services:
            raise ServiceIsNotRegistered(service)

        idc.Wait()
        with open(output, 'w') as out:
            self.services[service](out)
        idc.Exit(0)


class ServiceError(Exception):
    pass


class ServiceRegistrationError(ServiceError):
    pass


class ServiceAlreadyRegistered(ServiceRegistrationError):
    def __init__(self, name):
        self.name = name


class ServiceNameIsNotValid(ServiceRegistrationError):
    def __init__(self, name):
        self.name = name


class ServiceIsNotRegistered(ServiceError):
    def __init__(self, name):
        self.name = name


def is_valid_service_name(name):
    valid_syms = string.ascii_letters + '-_' + string.digits
    return set(name).issubset(valid_syms)
