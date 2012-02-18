import __builtin__
import gzip as _gzip
import os.path as _os_path


"""Openers by file extention.

Values should be callables such that::

  for line in opener(filename, mode):
      ...

will work.
"""
OPENERS = {
    '.gz': _gzip.open,
    }


def open(filename, openers=None):
    """Utility method that decompresses files based on their extension.

    Uses ``OPENERS`` to determine the appropriate opener for the
    file's extension.  If the extension is not listed in ``OPENERS``,
    fall back to the ``open`` builtin.
    """
    if openers is None:
        openers = OPENERS
    extension = _os_path.splitext(filename)[-1]
    opener = openers.get(extension, __builtin__.open)
    return opener(filename, 'r')
