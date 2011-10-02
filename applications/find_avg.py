#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
When you have acquired a list of flow sizes in a text file
use this script to extract δ from it.

δ is not supposed to be the average, but rather a suitable
factor that will sufficiently obfuscate packet lengths.

Usage: ./find_avg.py <filename>
'''

import sys
from functools import reduce
from itertools import tee
from operator  import add

def pairwise(l):
    a, b = tee(l)
    next(b, None)
    return zip(a, b)

# Read integer numbers from file and sort them ASC:
with open(sys.argv[1]) as fp:
    # Do not remove duplicates, as δ then becomes simply the average.
    values = sorted([int(e.strip()) for e in fp.readlines()])
    # Take pairwise combinations of values and calculate the total sum
    sum = reduce(add, [pair[1] - pair[0] for pair in pairwise(values)])
    # Compute and print the average
    print('δ has the value of: ' + str(sum / len(values)))
