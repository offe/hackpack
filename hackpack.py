#! /usr/bin/env python
from __future__ import with_statement

import pyDes
import hashlib
import os
import errno
import fnmatch
import sys
from StringIO import StringIO
from contextlib import closing
from zipfile import ZipFile

def mkdir_if_not_there(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else: raise

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

def get_locked_reward(reward_message_file, solution_output_file):
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
        if len(argv) > 3:
            args['directory'] = argv[3]
        else:
            # Extract in same directory as .hp-file is
            args['directory'] = os.path.split(args['file'])[0]
    elif action == 'build' and len(argv) > 2:
        args['directory'] = argv[2]
        if len(argv) > 3:
            args['file'] = argv[3]
        else:
            args['file'] = args['directory'] + '.hp'
    elif action == 'unlock' and len(argv) > 3:
        args['file'] = argv[2]
        args['execute'] = argv[3]
    else:
        raise CommandLineException('Missing parameters.')
    return action, args

def write_reward(f, out_file, reward_info_file, reward_dir=None):
    locked_reward = get_locked_reward(reward_info_file, out_file)
    f.write(locked_reward)

def build(file_name, dir_name):
    print 'building %s' % file_name
    print 'contents of %s:' % dir_name
    (output_dir, output_file_name) = os.path.split(file_name)
    (output_file_base, output_file_ext)=os.path.splitext(output_file_name)

    rewardfile_bases = []
    with closing(ZipFile(file_name, mode='w')) as zf:
        for root, dirnames, filenames in os.walk(dir_name):
            for f in fnmatch.filter(filenames, '*.in'):
                base = f[:-3]
                if all(base+'.'+ext in filenames for ext in ['out', 'rewardinfo']):
                    rewardfile_bases.append(base)
            to_copy = filenames[:]
            for reward_base in rewardfile_bases:
                to_copy.remove(reward_base+'.out')
                to_copy.remove(reward_base+'.rewardinfo')
                    
            print 'root', root
            print 'dirnames', dirnames
            print 'filenames', filenames
            print 'to_copy:\n', '\t'+'\n\t'.join(to_copy)
            print 'rewardfile_bases:\n', '\t'+'\n\t'.join(rewardfile_bases)

            for cfn in to_copy:
                zf.write(os.path.join(root, cfn), os.path.join(output_file_base, cfn))
            for rfb in rewardfile_bases:
                reward = StringIO()
                out_file = open(os.path.join(root, rfb+'.out'))
                info_file = open(os.path.join(root, rfb+'.rewardinfo'))
                write_reward(reward, out_file, info_file)
                zf.writestr(os.path.join(output_file_base, rfb+'.reward'), reward.getvalue())

def unpack(file_name, directory):
    zf = ZipFile(file_name, mode='r')
    namelist = zf.namelist()
    namelist.sort()
    for name in namelist:
        print name
        #if name.endswith('/'):
            #os.mkdir(os.path.join(directory, name))
        #else:
        needed_dir = os.path.join(directory, os.path.split(name)[0])
        print 'needed: ', needed_dir
        mkdir_if_not_there(os.path.join(directory, os.path.split(name)[0]))
        with open(os.path.join(directory, name), 'wb') as outfile:
            outfile.write(zf.read(name))


def main():
    action, args = parse_command_line(sys.argv)
    print action, args
    if action == 'build':
        build(args['file'], args['directory'])
    elif action == 'open':
        unpack(args['file'], args['directory']) 
    """
    solution_output_file = StringIO('''\
foo
bar
''')
    reward_message_file = StringIO('rosebud')
    locked_reward = get_locked_reward(reward_message_file, solution_output_file)
    locked_reward_file = StringIO(locked_reward)
    solution_output_file.seek(0)
    reward_message = unlock_reward(locked_reward_file, solution_output_file)
    print repr(reward_message)
    """

if __name__ == '__main__':
    main()
