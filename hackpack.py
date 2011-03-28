#! /usr/bin/env python

import pyDes
import hashlib
import os
import fnmatch
import sys
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
    return pyDes.triple_des(key, pyDes.CBC, "hackpack", padmode=pyDes.PAD_PKCS5)

def read_verified_data(f):
    '''
    >>> content = 'baz'
    >>> message = sha256(content) + content
    >>> read_verified_data(StringIO(message))
    'baz'
    >>> incorrectmessage = 32 * 'a' + content
    >>> read_verified_data(StringIO(incorrectmessage)) is None
    True
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

def lock_reward(reward_message_file, solution_output_file):
    key = hashkey(normalize_newlines(solution_output_file.read()))
    locked_reward = encrypt(key, reward_message_file.read())
    return locked_reward

def unlock_reward(reward_blob_file, solution_output_file):
    key = hashkey(normalize_newlines(solution_output_file.read()))
    reward_message = decrypt(key, reward_blob_file.read())
    return reward_message

class CommandLineException(Exception):
    def __init__(self, message):
        super(CommandLineException, self).__init__(message)

def parse_command_line(argv):
    if len(argv) < 2:
        raise CommandLineException('Missing action.')
    action = argv[1]
    args = {}
    if action == 'open' and len(argv) > 2:
        args['file'] = argv[2]
    elif action == 'build' and len(argv) > 2:
        args['file'] = argv[2]
        if len(argv) > 3:
            args['directory'] = argv[3]
        else:
            args['directory'] = os.path.splitext(args['file'])[0]
    elif action == 'unlock' and len(argv) > 3:
        args['file'] = argv[2]
        args['execute'] = argv[3]
    else:
        raise CommandLineException('Missing parameters.')
    return action, args

def build(file_name, dir_name):
    print 'building %s' % file_name
    print 'contents of %s:' % dir_name
    rewardfile_bases = []
    for root, dirnames, filenames in os.walk(dir_name):
        for f in fnmatch.filter(filenames, '*.in'):
            base = f[:-3]
            if all(base+'.'+ext in filenames for ext in ['out', 'rewardclear']):
                rewardfile_bases.append(base)
        to_copy = filenames[:]
        for reward_base in rewardfile_bases:
            def remove_if_present(a, e):
                if e in a:
                    a.remove(e)
            remove_if_present(to_copy, reward_base+'.out')
            remove_if_present(to_copy, reward_base+'.rewardclear')
                    
            print 'root', root
            print 'dirnames', dirnames
            print 'filenames', filenames
            print 'to_copy', to_copy
            print 'rewardfile_bases', rewardfile_bases

def main():
    action, args = parse_command_line(sys.argv)
    print action, args
    if action == 'build':
        build(args['file'], args['directory'])
    """
    solution_output_file = StringIO('''\
foo
bar
''')
    reward_message_file = StringIO('rosebud')
    locked_reward = lock_reward(reward_message_file, solution_output_file)
    locked_reward_file = StringIO(locked_reward)
    solution_output_file.seek(0)
    reward_message = unlock_reward(locked_reward_file, solution_output_file)
    print repr(reward_message)
    """

if __name__ == '__main__':
    main()
