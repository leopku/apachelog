from . import Processor as _Processor


class StatusProcessor (_Processor):
    r"""Track the status of requested files.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> from apachelog.processor import process
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET /style.css HTTP/1.1" 200 8240 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 404 560 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> sp = StatusProcessor()
    >>> process(stream, parser, [sp])
    >>> for request,status in sorted(sp.request.items()):
    ...     print('\t'.join([request, ', '.join(sorted(status))]))
    ... # doctest: +NORMALIZE_WHITESPACE
    GET / HTTP/1.1      200, 404
    GET /style.css HTTP/1.1     200
    >>> for status,request in sorted(sp.status.items()):
    ...     print('\t'.join([status, ', '.join(sorted(request))]))
    ... # doctest: +NORMALIZE_WHITESPACE
    200 GET / HTTP/1.1, GET /style.css HTTP/1.1
    404 GET / HTTP/1.1
    """
    def __init__(self):
        self.request = {}
        self.status = {}

    def process(self, data):
        request = data['%r']
        status = data['%>s']
        if request in self.request:
            self.request[request].add(status)
        else:
            self.request[request] = set([status])
        if status in self.status:
            self.status[status].add(request)
        else:
            self.status[status] = set([request])
