from astroid import MANAGER, register_module_extender
from astroid.builder import AstroidBuilder


CODE_FIX = """
class md5(object):
    def __init__(self, value=None):
        pass
    def hexdigest(self):
        return ''
    def update(self, x):
        return ''
    def digest(self):
        return ''

class sha1(object):
    def __init__(self, value=None):
        pass
    def hexdigest(self):
        return ''
    def update(self, x):
        return ''
    def digest(self):
        return ''

class sha512(object):
    def __init__(self, value=None):
        pass
    def hexdigest(self):
        return ''
    def update(self, x):
        return ''
    def digest(self):
        return ''

class sha256(object):
    def __init__(self, value=None):
        pass
    def hexdigest(self):
        return ''
    def update(self, x):
        return ''
    def digest(self):
        return ''
"""


def hashlib_transform():
    return AstroidBuilder(MANAGER).string_build(CODE_FIX)


def register(linter):
    register_module_extender(MANAGER, 'hashlib', hashlib_transform)
