# -*- encoding: utf-8 -*-

from __future__ import unicode_literals, absolute_import
from letsencrypt import (
    errors,
)
from letsencrypt.cli import (
    choose_configurator_plugins,
    _auth_from_domains,
    _find_domains,
    _suggest_donate,
)
from letsencrypt.display import ops as display_ops
from .helpers import (
    auth_from_domains_with_key,
    init_le_client,
)


# TODO: Make run as close to auth + install as possible
# Possible difficulties: args.csr was hacked into auth
def run(args, config, plugins):  # pylint: disable=too-many-branches,too-many-locals
    """Obtain a certificate and install."""
    try:
        installer, authenticator = choose_configurator_plugins(args, config, plugins, "run")
    except errors.PluginSelectionError, e:
        return e.message

    domains = _find_domains(args, installer)

    # TODO: Handle errors from _init_le_client?
    le_client = init_le_client(args, config, authenticator, installer)

    if args.private_key:
        lineage = auth_from_domains_with_key(le_client, config, domains, args.private_key)
    else:
        lineage = _auth_from_domains(le_client, config, domains)

    le_client.deploy_certificate(
        domains, lineage.privkey, lineage.cert,
        lineage.chain, lineage.fullchain)

    le_client.enhance_config(domains, config)

    if len(lineage.available_versions("cert")) == 1:
        display_ops.success_installation(domains)
    else:
        display_ops.success_renewal(domains)

    _suggest_donate()
