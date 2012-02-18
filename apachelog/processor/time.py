import datetime as _datetime

from ..date import parse_time as _parse_time
from . import Processor as _Processor


class LogTimeProcessor (_Processor):
    r"""Track the initial and final request times.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> from apachelog.processor import Processor, process
    >>> class PrintLogTimeProcessor (Processor):
    ...     def __init__(self, log_time_processor):
    ...         self.log_time_processor = log_time_processor
    ...     def process(self, data):
    ...         print('{}: {}'.format(data['%t'], self.log_time_processor.last_time))
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 561 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 200 561 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> ltp = LogTimeProcessor()
    >>> processors = [ltp, PrintLogTimeProcessor(ltp)]
    >>> process(stream, parser, processors)
    [18/Feb/2012:10:25:43 -0500]: 2012-02-18 10:25:43-05:00
    [18/Feb/2012:10:25:58 -0500]: 2012-02-18 10:25:58-05:00
    >>> ltp.total_seconds()
    15.0
    """
    def __init__(self):
        self.last_time = self.start_time = self.stop_time = None

    def process(self, data):
        time = _parse_time(data['%t'])
        self.last_time = time  # for use by subclasses or other processors
        if self.start_time is None or time < self.start_time:
            self.start_time = time
        if self.stop_time is None or time > self.stop_time:
            self.stop_time = time

    def total_seconds(self):
        if self.start_time is None:
            return 0
        dt = self.stop_time - self.start_time
        return dt.total_seconds()
