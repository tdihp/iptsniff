import re
from ast import literal_eval
import os

from iptsniff import *


def testsample(filename):
    with open(filename, 'r') as f:
        txt = f.read()

    m = re.match(r'setsockopt\(4, SOL_IP, IPT_SO_SET_REPLACE, (".*"), (\d+)\) = 0', txt)
    data = bytearray(literal_eval('b' + m.group(1)))
    assert len(data) == int(m.group(2))
    repl = ipt_replace.from_buffer(data)
    print_table(repl)


def main():
    tests = [
        'longsample',
        'foobarsample',
        'foobardup',
    ]
    for filename in tests:
        testsample(os.path.join('tests', filename))


if __name__ == '__main__':
    main()
