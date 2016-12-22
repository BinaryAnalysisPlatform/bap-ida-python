

class CommentHandlers(object):
    def __init__(self):
        self.handlers = []
        self.comments = {}

    def handler(self):
        def wrapped(func):
            self.register(func)
            return func
        return wrapped

    def register_handler(self, func):
        for handler in self.handlers:
            print(handler.__name__)
        self.handlers.append(func)

    def add(self, addr, key, value):
        if (addr, key) in self.comments:
            self.comments[(addr, key)].append(value)
        else:
            self.comments[(addr, key)] = [value]
        for handler in self.handlers:
            handler(addr, key, value)
