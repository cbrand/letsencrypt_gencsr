# -*- encoding: utf-8 -*-

import os
import logging
import zope.component
from letsencrypt import interfaces
from letsencrypt import le_util

logger = logging.getLogger(__name__)


# High level functions
def copy_key(input_key, key_dir, keyname="key-letsencrypt.pem"):
    """
    Copies the given key to into the key directory with the
    data format.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    :param le_util.Key input_key: The key which shoudl be copied
    :param str key_dir: Key save directory.
    :param str keyname: Filename of key

    :returns: Key
    :rtype: :class:`letsencrypt.le_util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """

    config = zope.component.getUtility(interfaces.IConfig)
    # Save file
    le_util.make_or_verify_dir(key_dir, 0o700, os.geteuid(),
                               config.strict_permissions)
    key_f, key_path = le_util.unique_file(
        os.path.join(key_dir, keyname), 0o600)
    if isinstance(input_key, basestring):
        key_pem = input_key
    else:
        key_pem = input_key[1]
    key_f.write(key_pem)
    key_f.close()

    logger.info("Copied key: %s", key_path)

    return le_util.Key(key_path, key_pem)
