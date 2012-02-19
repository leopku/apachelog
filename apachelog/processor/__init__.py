"""Define ``Processor`` classes for aggregating data across log files.
"""

class Processor (object):
    def process(self, data):
        pass


def process(stream, parser, processors):
    r"""Process a log with a list of processors.

    For each line in the log located at ``filename``, parse the line
    using ``parser`` and analyze it with each of the ``Processor``
    instances in the list ``processors``.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> class PrinthostProcessor (Processor):
    ...     def __init__(self, name):
    ...         self.name = name
    ...     def process(self, data):
    ...         print('{}: {}'.format(self.name, data['%h']))
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 561 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 200 561 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> processors = [PrinthostProcessor('a'), PrinthostProcessor('b')]
    >>> process(stream, parser, processors)
    a: 192.168.0.1
    b: 192.168.0.1
    a: 192.168.0.2
    b: 192.168.0.2
    """
    for line in stream:
        data = parser.parse(line)
        for processor in processors:
            processor.process(data)
