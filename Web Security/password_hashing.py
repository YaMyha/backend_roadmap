import os

import bcrypt
import scrypt

def use_bcrypt():
    salt = bcrypt.gensalt()
    password = "SecretPassword123"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    print(f"Salt: {salt}")
    print(f"Hashed Password: {hashed_password}")


def use_scrypt():
    salt = os.urandom(16)
    N = 16384  # parsmeter CPU/memory cost. Usually we choose extent of 2: 2^14 and etc
    r = 8      # parsmeter block size. Usually leave 8
    p = 1      # parsmeter parallelization. Usually leave 1 because more p can cause large load

    password = "SecretPassword123"

    hashed_password = scrypt.hash(password, salt=salt, N=N, r=r, p=p)

    print(f"Salt: {salt}")
    print(f"Hashed Password: {hashed_password}")

use_bcrypt()
use_scrypt()