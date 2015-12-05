# -*- encoding: utf-8 -*-

from letsencrypt import crypto_util
from letsencrypt import le_util
from letsencrypt.client import Client

from letsencrypt_gencsr.crypto_addition_util import copy_key


class KeyClient(Client):
    """ACME protocol client with an extension to support pre defined
     private keys.

    :ivar .IConfig config: Client configuration.
    :ivar .Account account: Account registered with `register`.
    :ivar .AuthHandler auth_handler: Authorizations handler that will
        dispatch DV and Continuity challenges to appropriate
        authenticators (providing `.IAuthenticator` interface).
    :ivar .IAuthenticator dv_auth: Prepared (`.IAuthenticator.prepare`)
        authenticator that can solve the `.constants.DV_CHALLENGES`.
    :ivar .IInstaller installer: Installer.
    :ivar acme.client.Client acme: Optional ACME client API handle.
       You might already have one from `register`.

    """

    def obtain_certificate_from_key(self, domains, key):
        """Obtains a certificate from the ACME server.

        `.register` must be called before `.obtain_certificate`

        :param set domains: domains to get a certificate
        :param str|le_util.Key key: the private key file of the domain.

        :returns: `.CertificateResource`, certificate chain (as
            returned by `.fetch_chain`), and newly generated private key
            (`.le_util.Key`) and DER-encoded Certificate Signing Request
            (`.le_util.CSR`).
        :rtype: tuple

        """

        key = le_util.Key(*key)

        # Create CSR from names
        key = copy_key(
            key, self.config.key_dir)
        csr = crypto_util.init_save_csr(key, domains, self.config.csr_dir)

        return self._obtain_certificate(domains, csr) + (key, csr)
