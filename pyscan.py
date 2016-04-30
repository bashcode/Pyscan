"""Pyscan - A fast malware scanner using ShellScannerPatterns

"""

__version__ = '1.12'


#!/usr/bin/env python

import os
import sys
import atexit
import getopt
import time
import urllib2
import logging
import hashlib
import datetime
from threading import Timer
if sys.version_info >= (2, 6, 0):
    from multiprocessing.pool import Pool
    from multiprocessing import cpu_count, Process, Manager, active_children
try:
    import re2 as re
except ImportError:
    import re


regex_list = []
regex_names = []
compiled = []

def test_regex(regex_array):
    """Ensures the regex strings are validated for proper syntax.

    """
    for regex_entry in regex_array:
        try:
            re.compile(regex_entry, re.MULTILINE | re.UNICODE)
        except re.error:
            logging.error('Invalid Regex Found: %s', regex_entry)
            sys.exit(1)


def find_all_files(desired_path):
    """Directory traversal for single-threaded scanning.

    """
    files = []
    for (dirpath, _, filenames) in os.walk(desired_path):
        for file_name in filenames:
            fullpath = os.path.join(dirpath, file_name)
            size = os.stat(fullpath).st_size # in bytes
            if size < 2000000:
                logging.debug('Found file: %s', fullpath)
                files.append(fullpath)
    return files


def explore_path(dir_queue, file_queue):
    """Directory traversal for multi-threaded scanning.

    """
    dir_queue_get = dir_queue.get
    dir_queue_put = dir_queue.put
    dir_queue_empty = dir_queue.empty
    file_queue_put = file_queue.put

    # File discovery using os.listdir in place of scandir.
    while 1:
        if dir_queue_empty():
            break
        else:
            ep_path = dir_queue_get()
            for file_name in os.listdir(ep_path):
                full_name = os.path.join(ep_path, file_name)
                if os.path.islink(full_name):
                    logging.info('Symlink:%s', file_name)
                if os.path.isdir(full_name) and not os.path.islink(full_name):
                    dir_queue_put(full_name)
                elif (os.path.isfile(full_name) and not
                    os.path.islink(full_name) and
                    os.lstat(full_name).st_size < 2000000):
                    logging.debug('Found file: %s', full_name)
                    file_queue_put(full_name)


def manager_process(dir_queue, file_queue, out_queue):
    """Dispatches and manages path and scanning workers.

    """
    pool = Pool()
    atexit.register(at_exit_manager, pool)
    logging.info('Gathering Files...')
    pool.apply(explore_path, (dir_queue, file_queue))
    logging.info('Files gathered. Scanning %s files...', file_queue.qsize())
    logging.info('Starting %s scan processes', cpu_count())
    print '~' * 79
    print_status(file_queue.qsize(), file_queue)
    for _ in range(6):
        pool.apply_async(parallel_scan, (file_queue, out_queue))
    pool.close()
    pool.join()
    out_queue.put(StopIteration)

def at_exit_main(manager):
    """Handles keyboard interrupts and ensures the manager process is properly terminated.

    """
    print 'Shutting down main process...'
    manager.terminate()
    sys.exit(1)

def at_exit_manager(pool):
    """Handles keyboard interrupts and ensures the scanner processes are properly terminated.

    """
    print 'Shutting down scanning processes...'
    pool.terminate()
    sys.exit(1)

def parallel_scan(file_queue, out_queue):
    """Scans files from input queue and places results in output queue.

    """
    file_queue_get = file_queue.get_nowait
    file_queue_empty = file_queue.empty
    out_queue_put = out_queue.put
    while 1:
        if file_queue_empty():
            break
        else:
            try:
                file_to_scan = file_queue_get()
                file_scan_results = file_scan(file_to_scan)
                if file_scan_results:
                    out_queue_put(file_scan_results)
            except IOError:
                pass


def file_scan(file_name):
    """Scans a single file and returns the results.

    """
    file_name = file_name.lstrip()
    try:
        logging.debug('Opening file: %s', file_name)
        file_contents = open(file_name).read()
        file_hash = hashlib.md5(file_contents).hexdigest()
        logging.debug('File %s: MD5 %s', file_name, file_hash)
    except IOError, io_error:
        return 'I/O error({0}): {1}: File:{2}'.format(io_error.errno, io_error.strerror, file_name)
    for malware_sig in compiled:
        found_malware = malware_sig.search(file_contents)
        if found_malware:
            index = compiled.index(malware_sig)
            return 'FOUND' + '::' + regex_names[index] + '::' + str(datetime.datetime.fromtimestamp(os.stat(file_name).st_ctime)) + '::' + repr(file_name)


def print_status(prev_files_left, file_queue):
    """Prints how many files are left to scan as well as the estimated speed.

    """
    cur_files_left = file_queue.qsize()
    print('Files(remain): '),
    print(str(cur_files_left)),
    print(' Speed(files/s): '),
    scan_speed = prev_files_left - cur_files_left
    prev_files_left = cur_files_left
    print(str(scan_speed)),
    print('\r'),
    sys.stdout.flush()
    if file_queue.qsize() == 0:
        return 0
    Timer(1.0, print_status, (prev_files_left, file_queue)).start()


def print_help():
    """Prints the usage table.

    """
    print 'Usage: ./pyscan.py [options]'
    print '-h, --help: This text.'
    print '-u [username], --user=[username]: Specifies a user to scan.'
    print '-c, --current: Specifies to scan the current directory.'

    sys.exit(1)


def main(argv):
    """Entry point.

    """
    try:
        opts, _ = getopt.getopt(argv, 'hu:cp', ['help', 'user=', 'current'])
    except getopt.GetoptError:
        print_help()
        sys.exit(1)
    desired_path = None
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print_help()
            sys.exit(1)
        elif opt in ('-u', '--user'):
            desired_path = os.path.expanduser('~' + arg) + '/public_html/'
        elif opt in ('-c', '--current'):
            desired_path = os.getcwd()
        elif opt in ('-p', '--path'):
            desired_path = arg

    if desired_path is None:
        print 'No path (-u or -c) option specified.'
        print_help()
        sys.exit(1)

    if os.path.exists(desired_path):
        logging.info('Scanning %s', desired_path)

    else:
        logging.error('Specified directory not found!')
        sys.exit(1)

        patterns = urllib2.urlopen('https://raw.githubusercontent.com/bashcode/Pyscan/master/ShellScannerPatterns')
        ilerminaty_patterns = urllib2.urlopen('https://raw.githubusercontent.com/bashcode/Pyscan/master/IlerminatyPatterns')

    for pattern in ilerminaty_patterns:
        pattern = pattern.strip()
        logging.debug('Loading Pattern:%s', pattern)
        regex_list.append(pattern.split('|', 1)[1])
        regex_names.append(pattern.split('_-')[1].split('-_')[0])

    # Reversed pattern order to match the new signatures first.
    for pattern in reversed(patterns.readlines()):
        pattern = pattern.strip()
        logging.debug('Loading Pattern:%s', pattern)

        # Code to skip an extremely slow rule.
        #if pattern.split('_-')[1].split('-_')[0] == "Attacker Names":
        #    logging.info('Skipping Attacker Names')
        #    continue

        regex_list.append(pattern.split('|', 1)[1])
        regex_names.append(pattern.split('_-')[1].split('-_')[0])

    test_regex(regex_list)
    for injection in regex_list:
        compiled.append(re.compile(injection, re.MULTILINE | re.UNICODE))

    # Parallel mode
    if sys.version_info >= (2, 6, 0):
        logging.info('Using parallel processes...')
        resource_manager = Manager()
        unsearched = resource_manager.Queue()
        unscanned = resource_manager.Queue()
        output_queue = resource_manager.Queue()
        unsearched.put(desired_path)
        manager = Process(target=manager_process, args=(unsearched, unscanned, output_queue))
        manager.start()
        atexit.register(at_exit_main, manager)

        output_queue_get = output_queue.get
        while 1:
            results = output_queue_get()
            if results is StopIteration:
                break
            else:
                logging.info('%s', results)
        print '~' * 79
        print ''
        print 'Account Scan Complete...'
        print 'Exiting...'
        print ''
        print ''

    # Single process mode
    else:
        logging.info('Using single process...')
        file_list = find_all_files(desired_path)
        logging.info('Files collected!')
        file_list_size = len(file_list)
        logging.info('Scanning %s total files...', file_list_size)
        for _, file_name in enumerate(file_list):
            logging.debug('Scanning %s', file_name)

            file_scan_results = file_scan(file_name)
            if file_scan_results:
                logging.info('%s', file_scan_results)
        logging.info('Account Scan Complete...')


if __name__ == '__main__':
    start_time = time.time()

    logging.basicConfig(level=logging.INFO
                        , filename=os.path.expanduser('~') + '/found_shells.log'
                        , filemode='a')

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

    if 're2' in sys.modules:
        logging.info('Loaded re2 module!')
    logging.info('Using version %s', __version__)
    main(sys.argv[1:])
    time_taken = time.time() - start_time
    logging.info('Ran in: ~~~ %s seconds ~~~', time_taken)
