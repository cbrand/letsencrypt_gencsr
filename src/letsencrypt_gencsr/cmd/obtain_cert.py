# -*- encoding: utf-8 -*-

from __future__ import unicode_literals, absolute_import
from letsencrypt.cli import (
    choose_configurator_plugins,
    _auth_from_domains,
    _find_domains,
    _report_new_cert,
    _suggest_donate,
)
from letsencrypt import (
    errors,
    le_util,
)
from letsencrypt_gencsr.cmd.helpers import auth_from_domains_with_key
from .helpers import init_le_client


def obtain_cert(args, config, plugins):
    """Authenticate & obtain cert, but do not install it."""

    if args.domains and args.csr is not None:
        # TODO: --csr could have a priority, when --domains is
        # supplied, check if CSR matches given domains?
        return "--domains and --csr are mutually exclusive"

    try:
        # installers are used in auth mode to determine domain names
        installer, authenticator = choose_configurator_plugins(args, config, plugins, "certonly")
    except errors.PluginSelectionError, e:
        return e.message

    # TODO: Handle errors from _init_le_client?
    le_client = init_le_client(args, config, authenticator, installer)

    # This is a special case; cert and chain are simply saved
    if args.csr is not None:
        certr, chain = le_client.obtain_certificate_from_csr(le_util.CSR(
            file=args.csr[0], data=args.csr[1], form="der"))
        cert_path, _, cert_fullchain = le_client.save_certificate(
            certr, chain, args.cert_path, args.chain_path, args.fullchain_path)
        _report_new_cert(cert_path, cert_fullchain)
    elif args.private_key:
        domains = _find_domains(args, installer)
        auth_from_domains_with_key(le_client, config, domains, key=args.private_key)
    else:
        domains = _find_domains(args, installer)
        _auth_from_domains(le_client, config, domains)

    _suggest_donate()
