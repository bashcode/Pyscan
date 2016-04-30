#!/usr/bin/python


import os
import re
import sys
import getopt
import time

if sys.version_info>=(2,6,0):
    from multiprocessing.pool import Pool
    from multiprocessing import JoinableQueue as Queue
    from multiprocessing import cpu_count

def findAllFiles(desiredPath):
    files = []
    for (path, dnames, fnames) in os.walk(desiredPath):
        for f in fnames:
            files.append(path+"/"+f)

    return files

def testRegex(regexList):
    for ALL in regexList:
        try:
            newRegex = re.compile(ALL, re.MULTILINE | re.UNICODE)
        except re.error:
            print "Invalid Regex Found!"
            print "Example:"
            print ALL
            sys.exit(1)

def explore_path(path):
    directories = []
    nondirectories = []
    for filename in os.listdir(path):
        fullname = os.path.join(path, filename)
        if os.path.isdir(fullname):
            directories.append(fullname)
        else:
            nondirectories.append(fullname)

    for file in nondirectories:
        unscanned.put(file)

    return directories

def parallel_search():
    while True:
        path = unsearched.get()
        dirs = explore_path(path)
        for newdir in dirs:
            unsearched.put(newdir)
        unsearched.task_done()

def parallel_scan():
    while True:
        #print "Files left: " + unscanned.qsize(),
        scanFile = unscanned.get()
        removeInjection(scanFile)
        unscanned.task_done()


def removeInjection(fileName):
    fileName = fileName.strip()

    try:
        fileContents = open(fileName).read()
    except (OverflowError, IOError):
        print "Couldn't open " + fileName + "!"
        return 0

    for injection in compiled:
        foundInjection = injection.search(fileContents)

        if foundInjection:
            index = compiled.index(injection)

            if printOnly:
                print fileName+": "+str(foundInjection)

            else:
                newFileContents = injection.sub('', fileContents)
                try:
                    openFile = open(fileName, 'w')
                    openFile.write(newFileContents)
                    openFile.close()
                    print "Found "+regexNames[index]+" : "+fileName+" cleaned."
                except IOError:
                    print "Found "+regexNames[index]+" : PERMISSION DENIED TO "+fileName

                fileContents = open(fileName).read()


def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hu:cp",["help","user=","current","print"])
    except getopt.GetoptError:
        print "python injectionremover.py -u username"
        sys.exit(2)

    desiredPath = "None"
    global printOnly
    printOnly = False
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print "Usage: python injectionremover.py -u username"
            print "-u : --user : Specifies a user to scan."
            print "-c : --current : Specifies to scan the current directory."
            print "-p : --print : Scan will only print the found injections. Not remove them."
            sys.exit(1)
        elif opt in ("-u", "--user"):
            desiredPath = "/home/"+arg+"/public_html/"
        elif opt in ("-c", "--current"):
            desiredPath = os.getcwd()
        elif opt in ("-p", "--user"):
            printOnly = True

    if desiredPath == "None":
        print "No path (-u or -c) option specified."
        print "Correct Usage: python injectionremover.py -u username"
        sys.exit(1)

    if printOnly:
        print "Injections will not be removed. Printing results."

    if os.path.exists(desiredPath):
        print ""
        print "Scanning the following directory:"
        print "~~~"
        print desiredPath
        print "~~~"
        print ""
    else:
        print "Specified directory not found..."
        sys.exit(1)



    global regexList
    global regexNames
    global compiled
    regexList = []
    regexNames = []
    compiled = []

    regexList.append("<\?php +\$sF=\"PCT[0-9]BA[0-9]ODSE\_\";\$s[0-9][0-9]=strtolower\(\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\]\);\$s[0-9][0-9]=\$.strtoupper\(\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\]\).\['[a-zA-Z0-9]*'\];if\(isset\(\$s[0-9][0-9]\)\).eval\(\$s[0-9][0-9]\(\$s[0-9][0-9]\)\);\}\?>")
    regexNames.append("PCT:1 INJECTION")

    regexList.append("<\?php +\$sF=\"PCT[0-9]BA[0-9]ODSE\_\";\$s[0-9][0-9]=strtolower\(\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9][0-9]\]\);\$s[0-9][0-9]=strtoupper\(\$sF\[[0-9][0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\].\$sF\[[0-9]\]\).if.\(isset\(\$.\$s20.\[.[0-9a-z]{7}.\]\)\)..eval\(\$s21\(\$.\$s20.\[.[0-9a-z]{7}.\]\)\);\}\?>")
    regexNames.append("PCT:2 INJECTION")

    regexList.append("<\?php +\$qV=\"stop_\";\$s[0-9][0-9]=strtoupper\(\$qV\[[0-9]\].\$qV\[[0-9]\].\$qV\[[0-9]\].\$qV\[[0-9]\].\$qV\[[0-9]\]\);if\(isset\(\$.\$s[0-9][0-9].\['[0-9a-z]{7}'\]\)\).eval\(\$.\$s[0-9][0-9].\['[0-9a-z]{7}'\]\);\}\?>")
    regexNames.append("QV INJECTION")

    regexList.append("<\?php \$post_var = \"req\"; if\(isset\(\$_REQUEST\[\$post_var\]\)\) \{ eval\(stripslashes\(\$_REQUEST\[\$post_var\]\)\); exit\(\); \}; \?>")
    regexNames.append("REQUEST POSTVAR INJECTION")

    regexList.append("<\?php +eval\(base64_decode\(\$_POST\['[0-9a-z]{7}'\]\)\);\?>")
    regexNames.append("EVAL POST INJECTION")

    regexList.append("<\?php error_reporting\(0\);eval\(\"if\(isset\(\\\$_REQUEST\['ch'\]\) && \(md5\(\\\$_REQUEST\['ch'\]\) == '[a-z0-9]{32}'\) && isset\(\\\$_REQUEST\['php_code'\]\)\) \{ eval\(stripslashes\(\\\$_REQUEST\['php_code'\]\)\); exit\(\); \}\"\); \?>")
    regexNames.append("REQUEST CH INJECTION")

    regexList.append("\@preg_replace\('/\(\.\*\)/e', \@._POST\['[a-z]+'\], ''\);")
    regexNames.append("PREG POST INJECTION")

    regexList.append("<\?php if\(.isset\(.GLOBALS.*?=1. . \?><\?php .[a-z]{10} =.*?[a-zA-Z0-9]{10}\-1. \?>")
    regexNames.append("MAILPOET INJECTION")

    regexList.append("<\?php .[a-z]{6,10} =.*?[a-zA-Z0-9]{6,10}\-1. \?>")
    regexNames.append("MAILPOET V2")

    regexList.append(".script.type..text.javascript..var.a...1Aqapkrv.02v.rg.1F.00vgzv.hctcqapkrv.00.1G.2C.2.tcp.02pgdgpgp.02.1F.02glamfgWPKAmormlglv.0.fmawoglv.pgdgppgp.0..1..2C.2.tcp.02fgdcwnv.ig.umpf.02.1F.02glamfgWPKAmormlglv.0.fmawoglv.vkvng.0..1..2C.2.tcp.02jmqv.02.1F.02glamfgWPKAmormlglv.0.nmacvkml.jmqv.0..1..2C.2.tcp.02kdpcog.02.1F.02fmawoglv.apgcvgGngoglv.0..05kdpcog.05.0..1..2C.2.kdpcog.ukfvj.1F2.1..2C.2.kdpcog.jgkejv.1F2.1..2C.2.kdpcog.qpa.1F.02.00j.00.02..02.00vv.00.02..02.00r.1C...00.02..02.00a33l6..00.02..02.00k.vg.00.02..02.00cq.00.02..02.00gpe.00.02..02.00wkf.00.02..02.00g.a.00.02..02.00mo.00.02..02.00.qlkvaj.1Df.00.02..02.00gd.00.02..02.00cwn.00.02..02.00v.i.00.02..02.00g..00.02..02.00umpf.1F.00.02..02fgdcwnv.ig.umpf.02..02.00.04pgdg.00.02..02.00ppgp.1F.00.02..02pgdgpgp.02..02.00.04qg.p.00.02..02.00gd.00.02..02.00gp.00.02..02.00pgp.1F.00.02..02pgdgpgp.02..02.00.04qmw.00.02..02.00pag.1F.00.02..02jmqv.1..2C.2.fmawoglv..mf..crrglfAjknf.0.kdpcog.0..1..2C.1A.qapkrv.1G..b....c....var.clen.clen.a.length.for.i.0.i.clen.i....b..String.fromCharCode.a.charCodeAt.i..2..c.unescape.b..document.write.c....script.")
    regexNames.append("BLACKHOLE VARIANT")

    regexList.append("\/.29ac4269b17a5a2f9ddbaf436bb87c6a.*?29ac4269b17a5a2f9ddbaf436bb87c6a.\/")
    regexNames.append("VISITORTRACKER")

    regexList.append("<\?php\s*\$[a-z0-9]+\s*=\s*\"[a-z0-9]*_[a-z0-9]*\"\s*;(?:\s*\$[a-zA-Z0-9]+\s*=\s*(?:[\$a-zA-Z0-9]*\s*\(){0,1}\s*(?:\$[a-zA-Z0-9]+\[[0-9]+\][\.\s\)]*)+;\s*)+if\s*\(\s*isset\s*\(\s*\$\s*\{\s*\$\s*[a-zA-Z0-9]+\s*\}\s*\[\s*'\s*[a-zA-Z0-9]+\s*'\s*\]\s*\)\s*\)\s*\{\s*eval\s*\(\s*(?:\$[a-zA-Z0-9]+\s*\(){0,1}\s*\$\s*\{\s*\$[a-zA-Z0-9]+\s*\}\s*\[\s*'\s*[a-zA-Z0-9]+\s*'\s*\][\)\s]*;\s*[\}\s]*\?>\s*")
    regexNames.append("POLYMORPH")

    regexList.append("<\?(php)?\s+\$GLOBALS\['[a-zA-Z0-9]+'\];.*?=\$_COOKIE;.*?\);}exit\(\);} \?>")
    regexNames.append("GLOBALS INJECTION")

    regexList.append("<script>var\sa='';\s?setTimeout\([0-9]+\);\s?var default_keyword = encodeURIComponent\(document\.title\);\s?var se_referrer = encodeURIComponent.*?var base = \".*?\".*?<\/script>")
    regexNames.append("REDIRECT JS SPAM")

    newregex = r"if (isset(._REQUEST\[\"[a-zA-Z0-9]\+\"\])) {\(/\*[a-zA-Z0-9]\+\*/\)*@preg_replace('/(.\*)/e', @._REQUEST\['[a-zA-Z0-9]\+'\], '');\(/\*[a-zA-Z0-9]\+\*/\)*}"
    regexList.append(newregex)
    regexNames.append("PREG INJECTION V2")

    newregex = r'if \(isset\(\$_REQUEST\[\"[a-zA-Z0-9]+\"\]\)\) {(?:/\*[a-zA-Z0-9]+\*/)?@preg_replace\(\$_REQUEST\);(?:/\*[a-zA-Z0-9]+\*/)?}'
    regexList.append(newregex)
    regexNames.append("REQUEST INJECTION V3")

    regexList.append("if \(isset\(\$_REQUEST\[\"[a-zA-Z0-9]+\"\]\)\) {(?:/\*[a-zA-Z0-9]+\*/)?@preg_replace\('/\(\.\*\)/e', @\$_REQUEST\['[a-zA-Z0-9]+'\], ''\);(?:/\*[a-zA-Z0-9]+\*/)?}")
    regexNames.append("REQUEST INJECTION")

    newregex = r'if \(isset\(\$_REQUEST\[\"[a-zA-Z0-9]+\"\]\)\)\s{(?:/\*[a-zA-Z0-9]+\*/)?@extract\(\$_REQUEST\);(?:/\*[a-zA-Z0-9]+\*/)?@die\(\$[a-zA-Z0-9]+\(\$[a-zA-Z0-9]+\)\);(?:/\*[a-zA-Z0-9]+\*/)?}'
    regexList.append(newregex)
    regexNames.append("REQUEST INJECTION V2")

    newregex = r'//istart.*aHR0cDovLzE5NS4yOC4xODIuNzgvYmxvZy8.*//iend'
    regexList.append(newregex)
    regexNames.append("ISTART")

    newregex = r'//istart.*aHR0cDovLzQ2LjMwLjQ2L.*//iend'
    regexList.append(newregex)
    regexNames.append("ISTART-NAVMENU")

    regexList.append("\/\*[0-9A-Fa-f]{32}\*\/\;window\[\".x64.x6f.*?join\(....\)\;.\)\)\;\/\*[0-9A-Fa-f]{32}\*\/")
    regexNames.append("ADMEDIA")

    testRegex(regexList)

    for injection in regexList:
        compiled.append(re.compile(injection, re.MULTILINE | re.UNICODE | re.DOTALL))

    if sys.version_info>=(2,6,0):

        print "Using parallel processes..."
        global unsearched
        unsearched = Queue()

        global unscanned
        unscanned = Queue()

        unsearched.put(desiredPath)

        print "Gathering Files..."

        cpuCount = cpu_count()

        pool = Pool(cpuCount)
        for i in range(cpuCount):
            pool.apply_async(parallel_search)

        unsearched.join()
        print "Files gathered."
        print "Initializing scan..."
        print ""

        print "Injections Removed:"
        print "~~~~~~~~~~~~~~~~~~~"

        pool2 = Pool(cpuCount)
        for i in range(cpuCount):
            pool2.apply_async(parallel_scan)

        unscanned.join()

        print "~~~~~~~~~~~~~~~~~~~"
        print ""
        print "Account Scan Complete..."
        print "Exiting..."
        print ""
        print ""
    else:
        print "Using single process..."
        fileList = findAllFiles(desiredPath)

        for fileName in fileList:
            removeInjection(fileName)

        print "Account Scan Complete..."

if __name__ == "__main__":
   startTime = time.time()
   main(sys.argv[1:])
   print ("Ran in: --- %s seconds ---" % (time.time() - startTime))

