#!/usr/bin/python
"""
This is a quick demo of the DEP module. Instructions regarding obtaining a
valid stoken.json file can be found in the docstring for the DEP module: dep.py.
Run this demo by calling it with the path to a valid stoken.json file:

$ python dep_demo.py /Users/admin/Documents/stoken.json
"""

from depy import DEPy
import sys
import os

mydep = DEPy()

try:
    stoken = sys.argv[1]
except IndexError:
    print 'No path to stoken.json given, aborting.'
    sys.exit(-1)

if not os.path.exists(stoken):
    print 'Path to stoken at %s not found, aborting.' % stoken
    sys.exit(-1)

mydep.init_stoken(stoken)

myinfo = mydep.account_info()
mydevices = mydep.get_devices()

print myinfo
print mydevices

devicelistcomplete = mydevices.get('more_to_follow')

print devicelistcomplete

deviceinfo = mydep.get_device_info('C02SOMESERIAL')

print deviceinfo
