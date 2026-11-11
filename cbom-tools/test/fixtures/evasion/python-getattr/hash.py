# Negative control 8: module and attribute are both assembled.
import importlib

_crypto = importlib.import_module('hash' + 'lib')


def digest(payload):
    return getattr(_crypto, 'sha' + '256')(payload).hexdigest()
