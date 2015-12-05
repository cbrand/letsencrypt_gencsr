# -*- encoding: utf-8 -*-

import OpenSSL
from letsencrypt.cli import (
    _treat_as_renewal,
    _report_new_cert
)
from letsencrypt import (
    crypto_util,
    errors,
)
from letsencrypt.cli import (
    logger,
    _determine_account,
)
from ..key_client import KeyClient


def auth_from_domains_with_key(le_client, config, domains, key):
    """Authenticate and enroll certificate.
    :param letsencrypt_gencsr.key_client.KeyClient le_client: The client
    """
    # Note: This can raise errors... caught above us though.
    lineage = _treat_as_renewal(config, domains)

    if lineage is not None:
        # TODO: schoen wishes to reuse key - discussion
        # https://github.com/letsencrypt/letsencrypt/pull/777/files#r40498574
        new_certr, new_chain, new_key, _ = le_client.obtain_certificate_from_key(domains, key)
        # TODO: Check whether it worked! <- or make sure errors are thrown (jdk)
        lineage.save_successor(
            lineage.latest_common_version(), OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, new_certr.body),
            new_key.pem, crypto_util.dump_pyopenssl_chain(new_chain))

        lineage.update_all_links_to(lineage.latest_common_version())
        # TODO: Check return value of save_successor
        # TODO: Also update lineage renewal config with any relevant
        #       configuration values from this attempt? <- Absolutely (jdkasten)
    else:
        # TREAT AS NEW REQUEST
        lineage = le_client.obtain_and_enroll_certificate(domains)
        if not lineage:
            raise errors.Error("Certificate could not be obtained")

    _report_new_cert(lineage.cert, lineage.fullchain)

    return lineage


def init_le_client(args, config, authenticator, installer):
    if authenticator is not None:
        # if authenticator was given, then we will need account...
        acc, acme = _determine_account(args, config)
        logger.debug("Picked account: %r", acc)
        # XXX
        # crypto_util.validate_key_csr(acc.key)
    else:
        acc, acme = None, None

    return KeyClient(config, acc, authenticator, installer, acme=acme)
