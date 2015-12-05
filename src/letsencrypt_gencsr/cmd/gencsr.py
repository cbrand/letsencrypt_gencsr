# -*- encoding: utf-8 -*-

from __future__ import unicode_literals, absolute_import, print_function
import os
from letsencrypt.crypto_util import init_save_csr
from letsencrypt.le_util import Key


def gencsr(args, config, plugins):
    if not args.private_key:
        print('The given key argument does not point to a file.')

    key = Key(*args.private_key)

    init_save_csr(
        key,
        args.domains,
        os.path.dirname(args.out) or '.',
        os.path.basename(args.out)
    )
