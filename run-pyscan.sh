#!/bin/bash

if [[ -f '/etc/redhat-release' && -n `grep -E "(CentOS release|CloudLinux Server release) 6" /etc/redhat-release` ]]; then
    if [[ $(arch) == "i686" ]]; then
        echo 'Using el6.i686 release'
        curl -ks "https://github.com/bashcode/Pyscan/raw/master/pyscan.el6.i686.zip" -o /root/pyscan.zip;
    else
        echo 'Using el6 release'
        curl -ks "https://github.com/bashcode/Pyscan/raw/master/pyscan.el6.zip" -o /root/pyscan.zip;
    fi
    unzip -qo /root/pyscan.zip -d /root/;
    rm -f /root/pyscan.zip;
    /root/pyscan.dist/pyscan.exe $@;
    rm -rf /root/pyscan.dist/;
elif [[ -f '/etc/redhat-release' && -n `cat /etc/redhat-release | grep -E "(CentOS release|CloudLinux Server release) 5"` ]]; then
    echo 'Using el5.i686 release'
    curl -ks "https://github.com/bashcode/Pyscan/raw/master/pyscan.el5.i686.zip" -o /root/pyscan.zip;
    unzip -qo /root/pyscan.zip -d /root/;
    rm -f /root/pyscan.zip;
    /root/pyscan.dist/pyscan.exe $@;
    rm -rf /root/pyscan.dist/;
elif [[ $(uname) == "MSYS_NT"* ]]; then
    python2.exe <(curl -k -s "https://github.com/bashcode/Pyscan/raw/master/pyscan.py") "$@"
else
    python <(curl -k -s "https://github.com/bashcode/Pyscan/raw/master/pyscan.py") "$@"
fi
