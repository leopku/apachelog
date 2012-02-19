from . import Processor as _Processor


class SetProcessor (_Processor):
    r"""Keep sets of values for particular data fields.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> from apachelog.processor import process
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET /style.css HTTP/1.1" 200 8240 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 404 560 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> sp = SetProcessor(keys=['%h', '%{User-Agent}i'])
    >>> process(stream, parser, [sp])
    >>> for key,values in sorted(sp.values.items()):
    ...     print('\t'.join([key, str(values)]))
    ... # doctest: +NORMALIZE_WHITESPACE
    %h  set(['192.168.0.2', '192.168.0.1'])
    %{User-Agent}i      set(['Mozilla/5.0 (...)'])
    """
    def __init__(self, keys):
        self.values = dict((k, set()) for k in keys)

    def process(self, data):
        for k in self.values.keys():
            self.values[k].add(data[k])
