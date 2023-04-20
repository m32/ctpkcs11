#!/usr/bin/env vpython3
import pickle
try:
    data = open('functions.called', 'rb').read()
    called = pickle.loads(data)
    del data
except:
    called = {}
fp = open('functions.rst', 'wt')
keys = sorted(called.keys())
for key in keys:
    v = '-+'[called[key]]
    fp.write('{} {}\n'.format(v, key))
fp.close()
