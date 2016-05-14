"""Pyscan - A fast malware scanner using ShellScannerPatterns

This version is still in testing/prototype stage.

"""

__version__ = '1.15a'

#!/usr/bin/env python

import os
import stat
import sys
import atexit
import time
import urllib2
import logging
import datetime
import thread
import optparse
import base64
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
            size = os.lstat(fullpath).st_size # in bytes
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
                file_stat = os.lstat(full_name)
                file_mode = file_stat.st_mode
                if S_ISLNK(file_mode):
                    logging.info('Symlink:%s. Skipping..', file_name) 
		    continue
                elif S_ISDIR(file_mode):
                    dir_queue_put(full_name)
                elif (S_ISREG(file_mode) and file_stat.st_size < 2000000):
                    logging.debug('Found file: %s', full_name)
                    if options.exclude_root_owner:
                        if file_stat.st_uid == 0 and file_stat.st_gid == 0:
                            logging.debug('File %s owned to root. Skipping..', full_name)
                            continue                   
                    file_queue_put(full_name)


def manager_process(dir_queue, file_queue, out_queue):
    """Dispatches and manages path and scanning workers.

    """
    pool = Pool(options.num_threads)
    atexit.register(at_exit_manager, pool)    
    logging.info('Gathering Files...')
    pool.apply(explore_path, (dir_queue, file_queue))
    logging.info('Files gathered. Scanning %s files...', file_queue.qsize())
    logging.info('Starting %s scan processes', options.num_threads)
    print '~' * 79
    thread.start_new_thread(print_status, (file_queue,))
    for _ in range(options.num_threads):
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
        f = open(file_name)
        file_contents = f.read()
        f.close()
    except IOError, io_error:
        return 'I/O error({0}): {1}: File:{2}'.format(io_error.errno, io_error.strerror, file_name)
    logging.debug('Scanning file: %s', file_name)
    for malware_sig in compiled:
        found_malware = malware_sig.search(file_contents)
        if found_malware:
            index = compiled.index(malware_sig)
            return 'FOUND' + '::' + regex_names[index] + '::' + str(datetime.datetime.fromtimestamp(os.lstat(file_name).st_ctime)) + '::' + repr(file_name)
    logging.debug('Done scanning file: %s', file_name)


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

def append_args_from_file(option, opt_str, value, parser):
    args = [arg.strip() for arg in open(value)]
    parser.values.include_dir.extend(args)

def parse_args():

    num_cpus = cpu_count()

    parser = optparse.OptionParser(version=__version__)
    parser.add_option('-p', '--path', action='append', type='string', dest='include_dir', metavar='PATH',
            help='Include given directory for scanning.')
    parser.add_option('-u', '--user', action='append', type='string', dest='include_user', metavar='USERNAME',
            help='Include given user\'s public_html path for scanning.')
    parser.add_option('--exclude', action='append', type='string', dest='exclude_dir', metavar='PATH',
            help='Exclude given directory from scanning.') 
    parser.add_option('-x','--exclude-root-owner', action='store_true', dest='exclude_root_owner',
            help='Exclude files owned by root from scanning.')
    parser.add_option('--include-from-file', action='callback', type='string', callback=append_args_from_file, metavar='FILE',
            help='Include list of directory for scanning from FILE')
    parser.add_option('-D', '--debug', action='store_true', dest='debug',
            help='Print debugging info.')
    parser.add_option('-t', '--threads', action='store', type='int', dest='num_threads', metavar='THREADS',
            help='Set number of threads to use for file scanning.')
    parser.set_defaults(include_dir=[], num_threads=num_cpus, exclude_dir=[], debug=False, include_user=[])
    global options
    (options, args) = parser.parse_args()

    #Hacky default setting.
    if not options.include_dir:
        options.include_dir = [os.getcwd()]
    
def main(argv):
    """Entry point.

    """
    parse_args()

    if options.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level
                        , filename=os.path.expanduser('~') + '/found_shells.log'
                        , filemode='a')

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(log_level)

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
    print base64.b64decode("""X19fX19fX19fX19fXyAgX19fX19fX19fX19fX19fX19fX18g
            X19fX19fXw0KX19fICBfXyBcXyAgLyAvIC9fICBfX18vICBfX18vICBfXyBgL18gIF
            9fIFwNCl9fICAvXy8gLyAgL18vIC9fKF9fICApLyAvX18gLyAvXy8gL18gIC8gLyAv
            DQpfICAuX19fL19cX18sIC8gL19fX18vIFxfX18vIFxfXyxfLyAvXy8gL18vDQovXy
            8gICAgIC9fX19fLw==""")
    main(sys.argv[1:])
    time_taken = time.time() - start_time
    print 'Ran in ' + str(time_taken) +  ' seconds.'
