#! /usr/bin/env python
from __future__ import with_statement

import pyDes
import hashlib
import os
import errno
import fnmatch
import shlex
import sys
from StringIO import StringIO
from contextlib import closing
from subprocess import Popen, PIPE
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

def read_verified_data(data):
    '''
    >>> content = 'baz'
    >>> message = sha256(content) + content
    >>> read_verified_data(StringIO(message))
    'baz'
    >>> incorrectmessage = 32 * 'a' + content
    >>> read_verified_data(StringIO(incorrectmessage)) is None
    True
    '''
    correct_hash = data[:32]
    data = data[32:]
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
    reward_message = reward_message_file.read()
    checksum = sha256(reward_message)
    locked_reward = encrypt(key, checksum + reward_message)
    return locked_reward

def unlock_reward(reward_blob_file, solution_output_file):
    key = hashkey(normalize_newlines(solution_output_file.read()))
    reward_message = decrypt(key, reward_blob_file.read())
    return reward_message

class CommandLineException(Exception):
    def __init__(self, message):
        super(CommandLineException, self).__init__(message)

def print_command_help(file_name, synopsis, description):
    print 'SYNOPSIS'
    print '   %s %s' % (file_name, synopsis)
    print
    print 'DESCRIPTION'
    for line in description.split('\n'):
        print '   %s' % line

def print_help(command=None):
    file_name = os.path.split(__file__)[1]
    default_help = ("""\
usage: %s <command> [<args>]

The commands are:
   build   Build a hackpack file from construction directory
   help    Show this help text
   open    Unpack hackpack file into a directory
   unlock  Unlock a rewardfile using a solution program

See '%s help <command> for more information on a specific command.'""" 
% (file_name, file_name))
    if command is None:
        print default_help
    elif command == 'open':
        print_command_help(file_name, 'open <file> [<directory>]', """\
Writes the contents of <file> into <directory>.
If no <directory> is given, the current working directory is used.""")
    elif command == 'build':
        print_command_help(file_name, 'build <directory> [<file>]', """\
Builds a hackpack named <file> from the contents of <directory>.
If no <file> is given, the name becomes <directory>.hp.""")
    elif command == 'unlock':
        print_command_help(file_name, 'unlock <reward> <command>', """\
Tries to unlock <reward> by running <command>.
The <command>'s stdin is fed by the reward's matching in-file.
	If the <command> writes the correct output to stdout the reward is unlocked.""")
    elif command == 'help':
        print_command_help(file_name, 'help [<command>]', """\
If no <command> is given shows a list of all commands.
If <commands> is given prints the synopsis and description of the command.""")
    else:
        print 'no help available. %s is not a hackpack command.' % command

def parse_command_line(argv):
    if len(argv) < 2:
        raise CommandLineException('Missing command.')
    command = argv[1]
    args = {}
    if command == 'open': 
        if len(argv) < 3:
            raise CommandLineException('Missing parameter.')
        args['file'] = argv[2]
        if len(argv) > 3:
            args['directory'] = argv[3]
        else:
            # Extract in same directory as .hp-file is
            args['directory'] = os.path.split(args['file'])[0]
    elif command == 'build':
        if len(argv) < 3:
            raise CommandLineException('Missing parameter.')
        args['directory'] = argv[2]
        if len(argv) > 3:
            args['file'] = argv[3]
        else:
            args['file'] = args['directory'] + '.hp'
    elif command == 'unlock':
        if len(argv) < 4:
            raise CommandLineException('Missing parameter.')
        args['file'] = argv[2]
        args['execute'] = argv[3]
    elif command == 'help':
        help_for = None if len(argv) < 3 else argv[2]
        print_help(help_for)
    else:
        raise CommandLineException('Unknown command.')
    return command, args

def write_reward(f, out_file, reward_info_file, reward_dir=None):
    locked_reward = get_locked_reward(reward_info_file, out_file)
    f.write(locked_reward)

def build(file_name, dir_name):
    print 'Building %s' % file_name
    print
    (output_dir, output_file_name) = os.path.split(file_name)
    (output_file_base, output_file_ext) = os.path.splitext(output_file_name)

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
                    
            for cfn in to_copy:
                full_file_name = os.path.join(root, cfn)
                print 'Adding %s' % full_file_name
                zf.write(full_file_name, os.path.join(output_file_base, cfn))
            for rfb in rewardfile_bases:
                reward_info_name = os.path.join(root, rfb+'.rewardinfo')
                print 'Building reward file for %s' % reward_info_name
                reward = StringIO()
                out_file = open(os.path.join(root, rfb+'.out'))
                info_file = open(reward_info_name)
                write_reward(reward, out_file, info_file)
                zf.writestr(os.path.join(output_file_base, rfb+'.reward'), reward.getvalue())
    print 
    print 'Build complete.'

def unpack(file_name, directory):
    zf = ZipFile(file_name, mode='r')
    namelist = zf.namelist()
    for name in namelist:
        needed_dir = os.path.join(directory, os.path.split(name)[0])
        mkdir_if_not_there(os.path.join(directory, os.path.split(name)[0]))
        out_name = os.path.join(directory, name)
        print 'Writing %s' % out_name
        with open(out_name, 'wb') as outfile:
            outfile.write(zf.read(name))
    print
    print 'Opening of hackpack complete.'


def unlock(file_name, solution):
    args = shlex.split(solution)
    p = Popen(args, stdin=PIPE, stdout=PIPE)
    in_file_name = os.path.splitext(file_name)[0] + '.in'
    in_f = open(in_file_name)
    out_data, _ = p.communicate(in_f.read())
    reward = unlock_reward(open(file_name), StringIO(out_data))
    reward_message = read_verified_data(reward)
    if reward_message is not None:
        print 'Reward successfully unlocked.'
        print
        print 'Message accessed:'
        print
        print reward_message
    else:
        print 'Failed to unlock reward.'

def main():
    try:
        action, args = parse_command_line(sys.argv)
        if action == 'build':
            build(args['file'], args['directory'])
        elif action == 'open':
            unpack(args['file'], args['directory']) 
        elif action == 'unlock':
            unlock(args['file'], args['execute']) 
    except CommandLineException, e:
        print e
        print "See '%s help'." % os.path.split(__file__)[1]

if __name__ == '__main__':
    main()
