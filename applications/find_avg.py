#!/usr/bin/env python
# When you have acquired a list of flow sizes in a text file
# use this script to extract δ from it.
#
# δ is not supposed to be the average, as is here, but rather
# a suitable factor that will sufficiently obfuscate packet lengths.
# Ergo, you may modify this at will to suit your purposes.
#
# Usage: ./find_avg.py <filename>

from functools import reduce
from itertools import tee
from operator  import add

def pairwise(l):
    a, b = tee(l)
    next(b, None)
    return zip(a, b)

# Read integer numbers from file, sort them ASC and remove duplicates:
with open(sys.argv[1]) as fp:
    values = sorted([int(e.strip()) for e in set(fp.readlines())])
    # Take pairwise combinations of values and calculate the total sum
    sum = reduce(add, [pair[1] - pair[0] for pair in pairwise(values)])
    # Compute and print the average
    print('δ has the value of:' + sum / len(values))
