"""Pyscan - A fast malware scanner using ShellScannerPatterns

This version is still in testing/prototype stage.

"""

__version__ = '1.12'

#!/usr/bin/env python

import os
import stat
import sys
import atexit
import time
import urllib2
import logging
import hashlib
import datetime
import thread
import optparse
from threading import Timer
from stat import *

try:
    import re2 as re
except ImportError:
    import re
try:
    from multiprocessing.pool import Pool
    from multiprocessing import cpu_count, Process, Manager, active_children
except ImportError:
    pass

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

            if ep_path in [ os.path.abspath(x) for x in options.exclude_dir ]:
                logging.info('Directory %s in excluded list! Skipping...', ep_path)
                continue

            for file_name in os.listdir(ep_path):
                full_name = os.path.join(ep_path, file_name)
                file_stat = os.stat(full_name)
                file_mode = file_stat.st_mode
                if S_ISLNK(file_mode):
                    logging.info('Symlink:%s. Skipping..', file_name)
                elif S_ISDIR(file_mode):
                    dir_queue_put(full_name)
                elif (S_ISREG(file_mode) and file_stat.st_size < 2000000):
                    logging.debug('Found file: %s', full_name)
                    if options.exclude_locked:
                        if file_stat.st_uid == 0 and file_stat.st_gid == 0:
                           logging.debug('File %s owned to root. Skipping..', full_name)
                           pass
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
    thread.start_new_thread(print_status, (file_queue,))
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


def print_status(file_queue):
    """Prints how many files are left to scan as well as the estimated speed.

    """
    prev_time = time.time()
    prev_files_left = file_queue.qsize()
    while file_queue.qsize() > 0:

        cur_time = time.time()
        delta_time = cur_time - prev_time

        cur_files_left = file_queue.qsize()
    	delta_files_left = prev_files_left - cur_files_left

        scan_speed = int(round(delta_files_left / delta_time))
        prev_files_left = cur_files_left
        prev_time = cur_time


	print('Files(remain): '),
    	print(str(cur_files_left)),
    	print(' Speed(files/s): '),
    	print(str(scan_speed)),
    	print('\r'),
    	sys.stdout.flush()
        time.sleep(1)

def parse_args():
    parser = optparse.OptionParser(version=__version__)
    parser.add_option('-p', '--path', action='append', type='string', dest='include_dir', default=[])
    parser.add_option('-u', '--user', action='append', type='string', dest='include_user', default=[])
    parser.add_option('--exclude-dir', action='append', type='string', dest='exclude_dir', default=[])
    parser.add_option('-x','--exclude-locked', action='store_true', dest='exclude_locked')
    global options
    (options, args) = parser.parse_args()

def main(argv):
    """Entry point.

    """
    parse_args()

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
    if 'multiprocessing' in sys.modules:
        logging.info('Loaded multiprocessing module!')
    else:
        logging.info('Multiprocessing not loaded!')
    logging.info('Using version %s', __version__)
    logging.info('For file name extraction, pipe list of detected files into: awk -F"::" \'{print $4}\'')

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

        regex_list.append(pattern.split('|', 1)[1])
        regex_names.append(pattern.split('_-')[1].split('-_')[0])

    test_regex(regex_list)
    for signature in regex_list:
        compiled.append(re.compile(signature, re.MULTILINE | re.UNICODE))

    # Parallel mode
    if 'multiprocessing' in sys.modules:
        logging.info('Using parallel processes...')
        resource_manager = Manager()
        unsearched = resource_manager.Queue()
        unscanned = resource_manager.Queue()
        output_queue = resource_manager.Queue()

        for path in options.include_dir:
            path = os.path.abspath(path)
            if os.path.exists(path):
                logging.info('Scanning %s', path)
                unsearched.put(path)
            else:
                logging.info('Path %s not found! Skipping..', path)
        for user in  options.include_user:
            if os.path.exists(user):
                logging.info('Scanning %s', user)
                unsearched.put(os.path.expanduser('~' + user) + '/public_html/')
            else:
               logging.info('User %s not found! Skipping..', user)


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
    main(sys.argv[1:])
    time_taken = time.time() - start_time
    print 'Ran in ' + str(time_taken) +  ' seconds.'
