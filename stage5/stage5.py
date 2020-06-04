#!/usr/bin/env python3

import sys
import hexdump
from kppy.database import KPDBv1
from kppy.exceptions import KPError

def load_db(filepath, password):
    db = KPDBv1(filepath, password, read_only=True)
    try:
        db.load()
    except KPError:
        return False
    return True

if __name__ == '__main__':

    if len(sys.argv) == 2:
        filepath = sys.argv[1]
    else:
        filepath='../Database.kdb'

    for i in range(0,65536):
        print(f'Trying key {i}')
        password_b = sys.stdin.buffer.read(20)
        # Convert to string to avoid KPError: filepath, masterkey and keyfile must be a string
        password_s = "".join([chr(c) for c in password_b])
        assert(len(password_s) == 20)
        if load_db(filepath, password_s):
            print('Key is good')
            hexdump.hexdump(password_b)
            sys.exit(0)

    sys.exit(1)

