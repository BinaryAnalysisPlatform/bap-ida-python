from .sexp import Parser

handlers = {}
filters = {}


class Loader(object):

    def __init__(self, *args):
        self.parser = Parser(*args)
        self.state = {}
        # the following are private, as we need to maintain
        # several invariants on them.
        self._handlers = []
        self._filters = []
        self._filter_reqs = set()

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def enable_handlers(self, names):
        """enables the given trace event handler and all its requirements.
        Example:

        >>> loader.enable_handler('regs')
        """
        self._handlers = satisfy_requirements(self._handlers + names)
        for name in self._handlers:
            handlers[name].init(self.state)

    def enable_filter(self, filter_name, *args, **kwargs):
        """turns on the specified filter.

        Passes all arguments to the filter with the given name.  The
        returned predicate is checked on each event and if it returns
        ``False`` then event handlers will not be called for that
        event.

        If a filter has requirements then those requirements are
        invoked before the filter, and are not affected by the
        predicates of other filters.


        Example:
        >>> loader.enable_filter('filter-machine', id=3)

        Or:
        >>> loader.enable_filter('filter-range', lo=0x400000, hi=0x400100)

        """
        filter = filters[filter_name]
        requires = satisfy_requirements(filter.requires)
        self.enable_handlers(requires)
        for req in requires:
            self._filter_reqs.add(req)
        self._filters.append(filter(*args, **kwargs))

    def next(self):
        event = self.parser.next()
        print('Parser event {}'.format(repr(event)))
        if len(event) != 2:
            raise ValueError('Malformed Observation {}'.format(event))
        event, payload = event
        completed = set()
        self.state['event'] = event

        # first run handlers that are required by filters
        for h in self._handlers:
            if h in self._filter_reqs and event in handlers[h].events:
                completed.add(h)
                handlers[h](self.state, payload)

        # now we can run all filters,
        for accept in self._filters:
            if not accept(self.state):
                break
        else:  # and if nobody complains then run the rest of handlers
            for h in self._handlers:
                if h not in completed and event in handlers[h].events:
                    handlers[h](self.state, payload)
        return self.state

    def run(self):
        for _ in next():
            pass


def attach_meta_attributes(h, **kwargs):
    """attaches meta attributes to the provided callable object ``h``

    The following attributes are attached to the ``__dict__``
    namespace (also available through the ``func_dict`` name):

    - ``'name'`` a normalized human readable name,
    computed from a function name with underscores substituted
    by dashes. If ``'name'`` is in ``kwargs``, then the provided
    name will be used instead.

    - ``'requires'`` a list handler dependencies. Will be empty if
    the ``requires`` keyword argument is not provided. Otherwise it
    will be intialized from the argument value, that could be a list
    or a string.

    - all other attributes from the ``kwargs`` argument.
    """
    if 'name' not in kwargs:
        name = h.__name__.replace('_', '-')
        h.__dict__['name'] = name
    req = kwargs.get('requires', [])
    if 'requires' in kwargs:
        del kwargs['requires']
    h.__dict__['requires'] = req if isinstance(req, list) else [req]
    h.__dict__.update(kwargs)


def handler(*args, **kwargs):
    """a decorator that creates a trace event handler

    Registers the provided function as an event handler for the
    specified list of events.  If enabled the function will be called
    every time one of the events occurs with two arguments - the
    trace loader state (which is a dictionary) and the payload of the
    occurred event, which is an s-expression represented as a list.

    The loader state is guaranteed to have the ``'event'`` attribute
    that will contain the name of the current event.

    Example:
    ```
    @handler('switch', 'fork')
    def machine_id(state, fromto):
        state['machine-id'] = fromto[1]

    ```
    """
    def make_handler(f):
        f.__dict__['events'] = args
        if 'init' in kwargs:
            default = kwargs['init']
            f.__dict__['init'] = lambda s: s.update(default)
            del kwargs['init']
        else:
            f.__dict__['init'] = lambda x: None
        attach_meta_attributes(f, **kwargs)
        handlers[f.name] = f
    return make_handler


def filter(**kwargs):
    """a decorator that creates a trace event filter

    The decorated function must accept the state dictionary
    and zero or more user provided arguments and return ``True``
    or ``False`` depending on whether the current event should be
    accepted or, correspondingly rejected.

    If the ``requires`` argument is passed to the filter decorator
    then the loader will ensure that all event handlers in ``requires``
    are run before the filter is called.

    Note: if a handler is required by any filter, then it will be
    always invoked, no matter whether its event is filtered or not.

    The decorator will also add several meta attributes to the
    decorated function (as described in ``attach_meta_attributes``)
    and update the global dictionary of available filters.

    Example:
    ```
    @filter(requires='pc')
    def filter_range(state, lo, hi):
        return lo <= state['pc'] <= hi
    ```
    """
    def make_filter(f):
        def init(**kwargs):
            return lambda state: f(state, **kwargs)
        attach_meta_attributes(f, **kwargs)
        attach_meta_attributes(init, name=f.name, **kwargs)
        filters[init.name] = init
    return make_filter


@handler('machine-switch', 'machine-fork', init={'machine-id': 0})
def machine_id(state, fromto):
    """tracks machine identifier

    Maintains the 'machine-id' field in the state.
    """
    state['machine-id'] = int(fromto[1])


@handler('pc-changed', init={'pc': 0})
def pc(state, data):
    """tracks program counter

    Maintains the 'pc' field in the state.
    """
    state['pc'] = word(data)['value']


@handler('enter-term', init={'term-id': None})
def term_id(state, data):
    """tracks term identifier

    Maintaints the 'term-id' field in the state.
    """
    state['term-id'] = data


@handler('pc-changed', 'written', init={'regs': {}})
def regs(state, data):
    """"tracks register assignments

    Provides the 'regs' field, which is a mapping from
    register names to values.
    """
    if state['event'] == 'pc-changed':
        state['regs'] = {}
    else:
        state['regs'][data[0]] = value(data[1])


@handler('pc-changed', 'stored', init={'mems': {}})
def mems(state, data):
    """tracks memory writes

    Provides the 'mems' field that represents all updates made by
    the current instruction to the memory in a form of a mapping
    from addresses to bytes. Both are represented with the Python
    int type
    """
    if state['event'] == 'pc-changed':
        state['mems'] = {}
    else:
        state['mems'][word(data[0])['value']] = value(data[1])


@filter(requires='pc')
def filter_range(state, lo, hi):
    """masks events that do not fall into the specified region.

    interval bounds are included.
    """
    return lo <= state['pc'] <= hi


@filter(requires='machine-id')
def filter_machine(state, id):
    "masks events that do not belong to the specified machine identifier"
    cur = state['machine-id']
    return cur == id if isinstance(id, int) else cur in id


def word(x):
    "parses a Primus word into a ``value``, ``type`` dictionary"
    w, t = x.split(':')
    return {
        'value': int(w, 0),
        'type': t
    }


def value(x):
    "parses a Primus value into a ``value``, ``type``, ``id`` dictionary"
    w, id = x.split('#')
    w = word(w)
    w['id'] = int(id)
    return w


def satisfy_requirements(requests):
    """ensures that each request gets what it ``requires``.

    Accepts a list of handler names and returns a list of handler
    names that guarantees that if a handler has a non-empty
    ``requires`` field, then all names in this list will precede the
    name of this handler. It also guarantees that each handler will
    occur at most once.
    """
    solution = []
    for name in requests:
        solution += satisfy_requirements(handlers[name].requires)
        solution.append(name)

    # now we need to dedup the solution - a handler must occur at most once
    result = []
    for h in solution:
        if h not in result:
            result.append(h)
    return result
