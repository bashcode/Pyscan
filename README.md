# Pyscan
Pyscan - A fast malware scanner using ShellScannerPatterns.
> Coded by Felipe Montes and Gerardo Smith

==

### Version
1.12

### Supported Platforms

* _CentOS 5/6/7_
* _CloudLinux 5/6/7_
* _Windows with https://msys2.github.io_
* cPanel - Plesk - Directadmin (other control panels not tested.)

### Usage Linux

Options..
* -c for current directory
* -u for scan username

```sh
perl <(GET https://raw.githubusercontent.com/bashcode/Pyscan/master/pyscan.py) 
```


### Usage Windows
```sh
Download, install, and run MSYS2
Run update-core to update the core packages.
Run pacman -S python2 python2-setuptools
For significantly faster scans, compile and install re2. Install the Pyton module with easy_install2.7 re2.
Use the function pyscan provided above.
```


