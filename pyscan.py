#!/usr/bin/env python

"""Pyscan - A fast malware scanner using ShellScannerPatterns

This version is still in testing/prototype stage.

"""

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
    from hashlib import sha1 as sha
except ImportError:
    from sha import new as sha

try:
    import re2 as re
except ImportError:
    import re
try:
    from multiprocessing.pool import Pool
    from multiprocessing import cpu_count, Process, Manager, active_children
except ImportError:
    pass

__version__ = '1.17'

regex_score = []
regex_tags = []
regex_list = []
regex_names = []
compiled = []
sha1_whitelist = []
sha1_blacklist = []

max_file_size = 2000000


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
            if options.skip_ext:
                for extension in options.skip_ext:
                    if file_name.endswith(extension):
                        logging.debug('File %s ends with extension %s. Skipping...',
                                      file_name, extension)
                        continue
            fullpath = os.path.join(dirpath, file_name)
            size = os.lstat(fullpath).st_size  # in bytes
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

            if ep_path in [os.path.abspath(x) for x in options.exclude_dir]:
                logging.info('Directory %s in excluded list! Skipping...',
                             ep_path)
                continue

            for file_name in os.listdir(ep_path):
                if options.skip_ext:
                    ext_found = False
                    for extension in options.skip_ext:
                        if file_name.endswith(extension):
                            logging.debug('File %s ends with extension %s. Skipping...',
                                          file_name, extension)
                            ext_found = True
                            break
                    if ext_found:
                        continue
                full_name = os.path.join(ep_path, file_name)
                file_stat = os.lstat(full_name)
                file_mode = file_stat.st_mode
                if S_ISLNK(file_mode):
                    logging.info('Symlink::%s. Skipping...', full_name)
                    continue
                elif S_ISDIR(file_mode):
                    dir_queue_put(full_name)
                elif (S_ISREG(file_mode) and file_stat.st_size < max_file_size):
                    logging.debug('Found file:: %s', full_name)
                    if options.exclude_root_owner:
                        if file_stat.st_uid == 0 and file_stat.st_gid == 0:
                            logging.debug('File %s owned by root user. Skipping...',
                                          full_name)
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
    logging.info('Starting %s scan processes...', options.num_threads)
    print '~' * 80
    thread.start_new_thread(print_status, (file_queue,))
    for _ in range(options.num_threads):
        pool.apply_async(parallel_scan, (file_queue, out_queue))
    pool.close()
    pool.join()
    out_queue.put(StopIteration)


def at_exit_main(manager):
    """Handles keyboard interrupts and ensures the manager process
       is properly terminated.

    """
    print 'Shutting down main process...'
    manager.terminate()
    sys.exit(1)


def at_exit_manager(pool):
    """Handles keyboard interrupts and ensures the scanner processes
       are properly terminated.

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
            file_to_scan = file_queue_get()
            file_scan_results = file_scan(file_to_scan)
            if file_scan_results:
                out_queue_put(file_scan_results)


def file_scan(file_name):
    """Scans a single file and returns the results.

    """
    file_name = file_name.lstrip()
    file_printed = repr(file_name)
    f = None
    try:
        logging.debug('Opening file: %s', file_printed)
        f = open(file_name)
        logging.debug('Reading file: %s', file_printed)
        file_contents = f.read()
        if f is not None:
            logging.debug('Closing file: %s',  file_printed)
            f.close()
    except (IOError, OSError), io_error:
        return 'I/O error({0}): {1}: File:{2}'.format(
            io_error.errno, io_error.strerror, file_printed
        )
    logging.debug('Scanning file: %s', file_printed)
    start_time = time.time()
    score = 0
    output_hits = ''
    output_ir = ''
    output_res = ''

    sha1_sum = sha(file_contents).hexdigest()
    logging.debug('sha sum: %s file: %s', sha1_sum, file_printed)

    if sha1_sum in sha1_whitelist:
                output_wl = 'FILE-WHITELIST::%s::SHA1_WL::%s' % (file_printed, sha1_sum)
                return output_wl
    if sha1_sum in sha1_blacklist:
                output_bl = 'FILE-HITS::%s::%s::SHA1_BL::%s\nFILE-RESULT::%s::%s::SHA1_BL::%s' % (
                    file_printed, datetime.datetime.fromtimestamp(
                        os.lstat(file_name).st_ctime
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    sha1_sum, file_printed,  
                    datetime.datetime.fromtimestamp(
                        os.lstat(file_name).st_ctime
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    sha1_sum
                )
                return output_bl
    sstag_phase_started = False
    for malware_sig in compiled:
        index = compiled.index(malware_sig)
        # Shell Pattern Phase starting.
        if regex_tags[index] == 'SSTag':
            sstag_phase_started = True
        # reading from the file again since injection removal phase ended. 
        if sstag_phase_started:
            try:
                logging.debug('Opening file: %s', file_printed)
                f = open(file_name)
                logging.debug('Reading file: %s', file_printed)
                file_contents = f.read()
                if f is not None:
                    logging.debug('Closing file: %s',  file_printed)
                    f.close()
            except (IOError, OSError), io_error:
                return 'I/O error({0}): {1}: File:{2}'.format(
                    io_error.errno, io_error.strerror, file_printed
                )                     
        found_malware = malware_sig.search(file_contents)
        if found_malware:
            score = score + regex_score[index]
            if regex_tags[index] == 'SSTag' and not output_hits:
                output_hits += 'FILE-HITS::%s::%s::%s::S::%d' % (
                    file_printed,
                    datetime.datetime.fromtimestamp(
                        os.lstat(file_name).st_ctime
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    regex_names[index],
                    regex_score[index]
                )
            elif regex_tags[index] == 'SSTag' and output_hits:
                output_hits += '::%s::S::%d' % (regex_names[index],
                                                 regex_score[index])
            elif regex_tags[index] == "IRTag":
                remove_results = remove_injection(file_name, malware_sig)
                output_ir += '%s::%s::%s::%s::S::%d\n' % (
                    remove_results,
                    file_printed,
                    datetime.datetime.fromtimestamp(
                        os.lstat(file_name).st_ctime
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    regex_names[index],
                    regex_score[index]
                )

    if output_hits or output_ir:
        output_hits = output_hits + '\n'
        if score >= 10:
            confidence = 'VERYHIGH'
        elif score < 10 and score > 5:
            confidence = 'HIGH'
        elif score == 5:
            confidence = 'MEDIUM'
        elif score < 5 and score > 0:
            confidence = 'LOW'
        elif score <= 0:
            confidence = 'LEGITIMATE(INJECTION)'

        output_res = 'FILE-RESULT::%s::%s::MALICIOUS_PROB_%s_%d' % (
            file_printed,
            str(datetime.datetime.fromtimestamp(os.lstat(file_name).st_ctime
            ).strftime('%Y-%m-%d %H:%M:%S')),
            confidence, score
        )
        time_taken = time.time() - start_time
        logging.debug('Finished file %s in %.2f seconds', file_printed, time_taken)
        output_final = [output_hits, output_ir, output_res]
        res = ''.join(filter(None, output_final))
        return res
    time_taken = time.time() - start_time
    logging.debug('Finished file %s in %.2f seconds', file_printed, time_taken)

def remove_injection(file_name, injection):
    """Takes in current file contents, the file name, and the compiled injection.
       Removes this injection from the file if the '-i' option is being used.

    """
    if options.remove_injections:
        file_printed = repr(file_name)
        logging.debug('Injection Remover Called: %s Injection: %s', file_printed, injection)
        try:
            logging.debug('Opening file: %s', file_printed)
            f = open(file_name, 'r+')
            file_contents = f.read()
            new_contents = injection.sub('', file_contents)
            f.seek(0)
            f.write(new_contents)
            f.truncate()
            return 'INJECTION-REMOVED'
            if f is not None:
                logging.debug('Closing file: %s',  file_printed)
                f.close()

        except (IOError, OSError), io_error:

            return 'INJECTION-REMOVAL-FAILED:I/O error({0}): {1}: File:{2}'.format(
                io_error.errno, io_error.strerror, file_printed
            )
    else:
        return 'INJECTION-FOUND'


def print_status(file_queue):
    """Prints how many files are left to scan as well as the estimated speed.

    """
    prev_time = time.time()
    prev_files_left = file_queue.qsize()
    while file_queue.qsize() > 0:

        time.sleep(1)
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


def append_args_from_file(option, opt_str, value, parser):
    """Callback function to include directory paths from a text file.

    """

    args = [arg.strip() for arg in open(value)]
    parser.values.include_dir.extend(args)

def available_cpus():
    try:
        return cpu_count()
    except (NotImplementedError, NameError):
        pass
    try:
        res = open('/proc/cpuinfo').read().count('processor\t:')

        if res > 0:
            return res
    except IOError:
        return 1

def parse_args():
    """Parses all arguments passed in from sys args.
    
    """

    num_cpus = available_cpus()

    parser = optparse.OptionParser(version=__version__)
    parser.add_option(
        '-p', '--path', action='append', type='string', dest='include_dir',
        metavar='PATH', help='Include given directory for scanning.'
    )
    parser.add_option(
        '-u', '--user', action='append', type='string', dest='include_user',
        metavar='USERNAME',
        help='Will include given user\'s public_html path for scanning.'
    )
    parser.add_option(
        '--exclude', action='append', type='string', dest='exclude_dir',
        metavar='PATH', help='Exclude given directory from scanning.'
    )
    parser.add_option(
        '-x', '--exclude-root-owner', action='store_true',
        dest='exclude_root_owner',
        help='Exclude files owned by root from scanning.'
    )
    parser.add_option(
        '--include-from-file', action='callback', type='string',
        callback=append_args_from_file, metavar='FILE',
        help='Include list of directories for scanning from FILE'
    )
    parser.add_option(
        '-D', '--debug', action='store_true', dest='debug',
        help='Print debugging info.'
    )
    parser.add_option(
        '-t', '--threads', action='store', type='int', dest='num_threads',
        metavar='THREADS',
        help='Set number of threads to use for file scanning.'
    )
    parser.add_option(
        '-i', '--injection', action='store_true', dest='remove_injections',
        help='Tells the scanner to remove known injections found.'
    )
    parser.add_option(
        '-l', '--legacy-mode', action='store_true', dest='legacy_mode',
        help='Start scanner in Single Process(legacy) mode.'
    )
    parser.set_defaults(
        include_dir=[], num_threads=num_cpus, exclude_dir=[],
        debug=False, include_user=[]
    )
    parser.add_option(
        '--skip-ext', action='append', type='string', dest='skip_ext',
        metavar='EXTENSION', 
        help='Skip scanning of all files with the specified extension.'
    )
    parser.add_option(
        '--scan-file', action='append', type='string', dest='scan_file',
        metavar='FILE',
        help='Scan a single given file(quick testing).'
    )

    global options
    (options, args) = parser.parse_args()

    # Hacky default setting.
    if not options.include_dir and not options.include_user:
        options.include_dir = [os.getcwd()]


def main(argv):
    """Entry point.

    """
    parse_args()

    if options.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        filename=os.path.expanduser('~') + '/found_shells.log',
        filemode='a',
        format='%(asctime)s:%(levelname)s:%(message)s',
        datefmt='%d/%b/%Y:%H:%M:%S'
    )

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

    patterns = urllib2.urlopen(
        'https://raw.githubusercontent.com/bashcode/Pyscan/master/ShellScannerPatterns'
    )

    # Sort alphabetically so IRTags go first. Second phase is SSTags. 
    patterns = sorted(patterns)

    sha1sums_whitelist = urllib2.urlopen(
        'https://raw.githubusercontent.com/bashcode/Pyscan/master/pyscan-sha1.whitelist'
    )
    sha1sums_blacklist = urllib2.urlopen(
        'https://raw.githubusercontent.com/bashcode/Pyscan/master/pyscan-sha1.blacklist'
    )

    for sha1sum in sha1sums_whitelist:
        sha1sum = sha1sum.strip()
        logging.debug('Load whitelisted SHA1:%s', sha1sum)
        sha1_whitelist.append(sha1sum.split(' ')[0])

    for sha1sum in sha1sums_blacklist:
        sha1sum = sha1sum.strip()
        logging.debug('Load blacklisted SHA1:%s', sha1sum)
        sha1_blacklist.append(sha1sum.split(' ')[0])

    for pattern in patterns:
        pattern = pattern.strip()
        logging.debug('Loading Pattern:%s', pattern)

        regex_score.append(
            int(pattern.split('|', 1)[0].split('-_')[1].split(':')[1])
        )
        regex_list.append(pattern.split('|', 1)[1])
        regex_names.append(pattern.split('_-')[1].split('-_')[0])
        regex_tags.append(pattern.split('_-')[0])

    test_regex(regex_list)
    for signature in regex_list:
        compiled.append(re.compile(signature, re.MULTILINE | re.UNICODE))

    if options.scan_file:
        for file in options.scan_file:
            if os.path.exists(file):
                logging.info('Scanning %s ...', file)
                file_scan_results = file_scan(file)
                if file_scan_results:
                    logging.info('%s', file_scan_results)
            else:
                logging.info('File %s doesn\'t exist? Please check the path.', file)
        logging.info('Scan Complete...')
        sys.exit(0)

    # Single process mode
    if options.legacy_mode or 'multiprocessing' not in sys.modules:
        logging.info('Using single process...')
        file_list = []
        for path in options.include_dir:
            path = os.path.abspath(path)
            if os.path.exists(path):
                logging.info('Scanning %s', path)
                file_list.extend(find_all_files(path))
            else:
                logging.info('Path %s not found! Skipping..', path)
        for user in options.include_user:
            user_path = os.path.expanduser('~' + user) + '/public_html/'
            if os.path.exists(user_path):
                logging.info('Scanning %s', user_path)
                file_list.extend(find_all_files(path))
            else:
                logging.info('User %s not found! Skipping...', user)

        logging.info('Files collected!')
        file_list_size = len(file_list)
        logging.info('Scanning %s total files...', file_list_size)
        for _, file_name in enumerate(file_list):
            logging.debug('Scanning %s', file_name)

            file_scan_results = file_scan(file_name)
            if file_scan_results:
                logging.info('%s', file_scan_results)
        logging.info('Scan Complete...')

    # Parallel mode
    else:
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
                logging.info('Path %s not found! Skipping...', path)
        for user in options.include_user:
            user_path = os.path.expanduser('~' + user) + '/public_html/'
            if os.path.exists(user_path):
                logging.info('Scanning %s', user_path)
                unsearched.put(user_path)
            else:
                logging.info('User %s not found! Skipping...', user)

        manager = Process(
            target=manager_process, args=(unsearched, unscanned,
                                          output_queue)
        )
        manager.start()
        atexit.register(at_exit_main, manager)
        output_queue_get = output_queue.get
        while 1:
            results = output_queue_get()
            if results is StopIteration:
                break
            else:
                results = results.splitlines()
                for result in results:
                    logging.info('%s', result)
        print '~' * 80
        print ''
        logging.info('Scan Complete... Exiting...')

if __name__ == '__main__':
    start_time = time.time()
    print base64.b64decode("""X19fX19fX19fX19fXyAgX19fX19fX19fX19fX19fX19fX18g
            X19fX19fXw0KX19fICBfXyBcXyAgLyAvIC9fICBfX18vICBfX18vICBfXyBgL18gIF
            9fIFwNCl9fICAvXy8gLyAgL18vIC9fKF9fICApLyAvX18gLyAvXy8gL18gIC8gLyAv
            DQpfICAuX19fL19cX18sIC8gL19fX18vIFxfX18vIFxfXyxfLyAvXy8gL18vDQovXy
            8gICAgIC9fX19fLw==""")
    main(sys.argv[1:])
    time_taken = time.time() - start_time
    print 'Ran in %.2f seconds.' % (time_taken)