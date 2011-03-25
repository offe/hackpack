#! /usr/bin/env python

import pyDes
import hashlib
from StringIO import StringIO

def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()

def hashkey(data):
    return sha256(data)[:24]

def normalize_newlines(data):
    '''Convert different types of newlines into lf (unix style).

    >>> normalize_newlines('foo\\r\\nbar\\r\\n')
    'foo\\nbar\\n'
    >>> normalize_newlines('foo\\nbar\\n')
    'foo\\nbar\\n'
    >>> normalize_newlines('foo\\nbar')
    'foo\\nbar\\n'

    Unfortunately it does not work for old mac format:
    >>> normalize_newlines('foo\\rbar\\r')
    'foo\\rbar\\n'
    '''
    return ''.join(line.rstrip()+'\n'
                   for line in StringIO(data))

def make_3des_key(key):
    return pyDes.triple_des(key, pyDes.CBC, 8*"\x00", pad=None,
                            padmode=pyDes.PAD_PKCS5)

def read_verified_data(f):
    '''
    >>> content = 'baz'
    >>> message = sha256(content) + content
    >>> read_verified_data(StringIO(message))
    'baz'
    '''
    correct_hash = f.read(32)
    data = f.read()
    if sha256(data) == correct_hash:
        return data
    else:
        return None

def encrypt(key, data):
    return make_3des_key(key).encrypt(data)

def decrypt(key, data):
    return make_3des_key(key).decrypt(data)

def build_pack():
    solution_output = '''\
foo
bar
'''
    key = hashkey(normalize_newlines(solution_output))
    print len(key), repr(key)
    c = encrypt(key, 'foo')
    print repr(c)
    print decrypt(key, c)

def main():
    build_pack()

if __name__ == '__main__':
    main()
