# -*- encoding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import argparse
import atexit
import functools
import json
import sys

import letsencrypt
import os
import zope.component
from letsencrypt import (
    cli,
    configuration,
    constants,
    interfaces,
    le_util,
    reporter,
)
from letsencrypt.cli import (
    flag_default,
    config_help,
    logger,
    _handle_exception,
    _cli_log_handler,
    setup_logging,
    HelpfulArgumentParser as OriginalHelpfulArgumentParser,
    DomainFlagProcessor,
    read_file,
    WebrootPathProcessor,
)
from letsencrypt.display import util as display_util
from letsencrypt.plugins import disco as plugins_disco
from .cmd.gencsr import gencsr

from letsencrypt_gencsr.cmd.obtain_cert import obtain_cert

ARGUMENT_PARSER_VERBS = OriginalHelpfulArgumentParser.VERBS.copy()
ARGUMENT_PARSER_VERBS.update(
    auth=obtain_cert,
    certonly=obtain_cert,
    gencsr=gencsr,
)
ARGUMENT_HELP_TOPICS = OriginalHelpfulArgumentParser.HELP_TOPICS[:]
ARGUMENT_HELP_TOPICS = ARGUMENT_HELP_TOPICS + [
    key for key in ARGUMENT_PARSER_VERBS.keys()
    if key not in ARGUMENT_HELP_TOPICS
    ]


class HelpfulArgumentParser(OriginalHelpfulArgumentParser):
    """Argparse Wrapper.

    This class wraps argparse, adding the ability to make --help less
    verbose, and request help on specific subcategories at a time, eg
    'letsencrypt --help security' for security options.

    Changes the original entry to be able to use a pre existing key.
    """

    # Maps verbs/subcommands to the functions that implement them
    VERBS = ARGUMENT_PARSER_VERBS

    # List of topics for which additional help can be provided
    HELP_TOPICS = ARGUMENT_HELP_TOPICS


def prepare_and_parse_args(plugins, args):
    """Returns parsed command line arguments.

    :param .PluginsRegistry plugins: available plugins
    :param list args: command line arguments with the program name removed

    :returns: parsed command line arguments
    :rtype: argparse.Namespace

    """
    helpful = HelpfulArgumentParser(args, plugins)

    # --help is automatically provided by argparse
    helpful.add(
        None, "-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"),
        help="This flag can be used multiple times to incrementally increase the verbosity of output, "
             "e.g. -vvv."
    )
    helpful.add(
        None, "-t", "--text", dest="text_mode", action="store_true",
        help="Use the text output instead of the curses UI."
    )
    helpful.add(
        None, "--register-unsafely-without-email", action="store_true",
        help="Specifying this flag enables registering an account with no "
             "email address. This is strongly discouraged, because in the "
             "event of key loss or account compromise you will irrevocably "
             "lose access to your account. You will also be unable to receive "
             "notice about impending expiration of revocation of your "
             "certificates. Updates to the Subscriber Agreement will still "
             "affect you, and will be effective 14 days after posting an "
             "update to the web site."
    )
    helpful.add(None, "-m", "--email", help=config_help("email"))
    # positional arg shadows --domains, instead of appending, and
    # --domains is useful, because it can be stored in config
    # for subparser in parser_run, parser_auth, parser_install:
    #    subparser.add_argument("domains", nargs="*", metavar="domain")
    helpful.add(None, "-d", "--domains", "--domain", dest="domains",
                metavar="DOMAIN", action=DomainFlagProcessor, default=[],
                help="Domain names to apply. For multiple domains you can use "
                     "multiple -d flags or enter a comma separated list of domains "
                     "as a parameter.")
    helpful.add(
        None, "--duplicate", dest="duplicate", action="store_true",
        help="Allow getting a certificate that duplicates an existing one")

    helpful.add_group(
        "automation",
        description="Arguments for automating execution & other tweaks")
    helpful.add(
        "automation", "--version", action="version",
        version="%(prog)s {0}".format(letsencrypt.__version__),
        help="show program's version number and exit")
    helpful.add(
        "automation", "--renew-by-default", action="store_true",
        help="Select renewal by default when domains are a superset of a "
             "previously attained cert")
    helpful.add(
        "automation", "--agree-tos", dest="tos", action="store_true",
        help="Agree to the Let's Encrypt Subscriber Agreement")
    helpful.add(
        "automation", "--account", metavar="ACCOUNT_ID",
        help="Account ID to use")

    helpful.add_group(
        "testing", description="The following flags are meant for "
                               "testing purposes only! Do NOT change them, unless you "
                               "really know what you're doing!")
    helpful.add(
        "testing", "--debug", action="store_true",
        help="Show tracebacks in case of errors, and allow letsencrypt-auto "
             "execution on experimental platforms")
    helpful.add(
        "testing", "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    helpful.add(
        "testing", "--tls-sni-01-port", type=int,
        default=flag_default("tls_sni_01_port"),
        help=config_help("tls_sni_01_port"))
    helpful.add(
        "testing", "--http-01-port", type=int, dest="http01_port",
        default=flag_default("http01_port"), help=config_help("http01_port"))

    helpful.add_group(
        "security", description="Security parameters & server settings")
    helpful.add(
        "security", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    helpful.add(
        "security", "--redirect", action="store_true",
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.", dest="redirect", default=None)
    helpful.add(
        "security", "--no-redirect", action="store_false",
        help="Do not automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.", dest="redirect", default=None)
    helpful.add(
        "security", "--hsts", action="store_true",
        help="Add the Strict-Transport-Security header to every HTTP response."
             " Forcing browser to use always use SSL for the domain."
             " Defends against SSL Stripping.", dest="hsts", default=False)
    helpful.add(
        "security", "--no-hsts", action="store_false",
        help="Do not automatically add the Strict-Transport-Security header"
             " to every HTTP response.", dest="hsts", default=False)
    helpful.add(
        "security", "--uir", action="store_true",
        help="Add the \"Content-Security-Policy: upgrade-insecure-requests\""
             " header to every HTTP response. Forcing the browser to use"
             " https:// for every http:// resource.", dest="uir", default=None)
    helpful.add(
        "security", "--no-uir", action="store_false",
        help=" Do not automatically set the \"Content-Security-Policy:"
             " upgrade-insecure-requests\" header to every HTTP response.",
        dest="uir", default=None)
    helpful.add(
        "security", "--strict-permissions", action="store_true",
        help="Require that all configuration files are owned by the current "
             "user; only needed if your config is somewhere unsafe like /tmp/")

    helpful.add_deprecated_argument("--agree-dev-preview", 0)

    _create_subparsers(helpful)
    _paths_parser(helpful)
    # _plugins_parsing should be the last thing to act upon the main
    # parser (--help should display plugin-specific options last)
    _plugins_parsing(helpful, plugins)

    return helpful.parse_args()


def _create_subparsers(helpful):
    helpful.add_group("certonly", description="Options for modifying how a cert is obtained")
    helpful.add_group("gencsr", description="Generates a CSR file for the passed domains")
    helpful.add_group("install", description="Options for modifying how a cert is deployed")
    helpful.add_group("revoke", description="Options for revocation of certs")
    helpful.add_group("rollback", description="Options for reverting config changes")
    helpful.add_group("plugins", description="Plugin options")
    helpful.add(
        None, "--user-agent", default=None,
        help="Set a custom user agent string for the client. User agent strings allow "
             "the CA to collect high level statistics about success rates by OS and "
             "plugin. If you wish to hide your server OS version from the Let's "
             'Encrypt server, set this to "".')
    helpful.add("certonly",
                "--csr", type=read_file,
                help="Path to a Certificate Signing Request (CSR) in DER"
                     " format; note that the .csr file *must* contain a Subject"
                     " Alternative Name field for each domain you want certified.")
    helpful.add("certonly",
                "--key",
                "--private-key", type=read_file,
                help="The path of the certificate",
                dest='private_key'
                )
    helpful.add("gencsr",
                "--out", type=str,
                help='The file location the csr should be exported to.',
                dest='out')
    helpful.add("rollback",
                "--checkpoints", type=int, metavar="N",
                default=flag_default("rollback_checkpoints"),
                help="Revert configuration N number of checkpoints.")
    helpful.add("plugins",
                "--init", action="store_true", help="Initialize plugins.")
    helpful.add("plugins",
                "--prepare", action="store_true", help="Initialize and prepare plugins.")
    helpful.add("plugins",
                "--authenticators", action="append_const", dest="ifaces",
                const=interfaces.IAuthenticator, help="Limit to authenticator plugins only.")
    helpful.add("plugins",
                "--installers", action="append_const", dest="ifaces",
                const=interfaces.IInstaller, help="Limit to installer plugins only.")


def _paths_parser(helpful):
    add = helpful.add
    verb = helpful.verb
    if verb == "help":
        verb = helpful.help_arg
    helpful.add_group(
        "paths", description="Arguments changing execution paths & servers")

    cph = "Path to where cert is saved (with auth --csr), installed from or revoked."
    section = "paths"
    if verb in ("install", "revoke", "certonly"):
        section = verb
    if verb == "certonly":
        add(section, "--cert-path", type=os.path.abspath,
            default=flag_default("auth_cert_path"), help=cph)
    elif verb == "revoke":
        add(section, "--cert-path", type=read_file, required=True, help=cph)
    else:
        add(section, "--cert-path", type=os.path.abspath,
            help=cph, required=(verb == "install"))

    section = "paths"
    if verb in ("install", "revoke"):
        section = verb
    # revoke --key-path reads a file, install --key-path takes a string
    add(section, "--key-path", required=(verb == "install"),
        type=((verb == "revoke" and read_file) or os.path.abspath),
        help="Path to private key for cert installation "
             "or revocation (if account key is missing)")

    default_cp = None
    if verb == "certonly":
        default_cp = flag_default("auth_chain_path")
    add("paths", "--fullchain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a full certificate chain (cert plus chain).")
    add("paths", "--chain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a certificate chain.")
    add("paths", "--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("paths", "--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("paths", "--logs-dir", default=flag_default("logs_dir"),
        help="Logs directory.")
    add("paths", "--server", default=flag_default("server"),
        help=config_help("server"))


def _plugins_parsing(helpful, plugins):
    helpful.add_group(
        "plugins", description="Let's Encrypt client supports an "
                               "extensible plugins architecture. See '%(prog)s plugins' for a "
                               "list of all installed plugins and their names. You can force "
                               "a particular plugin by setting options provided below. Further "
                               "down this help message you will find plugin-specific options "
                               "(prefixed by --{plugin_name}).")
    helpful.add(
        "plugins", "-a", "--authenticator", help="Authenticator plugin name.")
    helpful.add(
        "plugins", "-i", "--installer", help="Installer plugin name (also used to find domains).")
    helpful.add(
        "plugins", "--configurator", help="Name of the plugin that is "
                                          "both an authenticator and an installer. Should not be used "
                                          "together with --authenticator or --installer.")
    helpful.add("plugins", "--apache", action="store_true",
                help="Obtain and install certs using Apache")
    helpful.add("plugins", "--nginx", action="store_true",
                help="Obtain and install certs using Nginx")
    helpful.add("plugins", "--standalone", action="store_true",
                help='Obtain certs using a "standalone" webserver.')
    helpful.add("plugins", "--manual", action="store_true",
                help='Provide laborious manual instructions for obtaining a cert')
    helpful.add("plugins", "--webroot", action="store_true",
                help='Obtain certs by placing files in a webroot directory.')

    # things should not be reorder past/pre this comment:
    # plugins_group should be displayed in --help before plugin
    # specific groups (so that plugins_group.description makes sense)

    helpful.add_plugin_args(plugins)

    # These would normally be a flag within the webroot plugin, but because
    # they are parsed in conjunction with --domains, they live here for
    # legibiility. helpful.add_plugin_ags must be called first to add the
    # "webroot" topic
    helpful.add("webroot", "-w", "--webroot-path", action=WebrootPathProcessor,
                help="public_html / webroot path. This can be specified multiple times to "
                     "handle different domains; each domain will have the webroot path that"
                     " preceded it.  For instance: `-w /var/www/example -d example.com -d "
                     "www.example.com -w /var/www/thing -d thing.net -d m.thing.net`")
    parse_dict = lambda s: dict(json.loads(s))
    # --webroot-map still has some awkward properties, so it is undocumented
    helpful.add("webroot", "--webroot-map", default={}, type=parse_dict,
                help=argparse.SUPPRESS)


def init_key_arguments(parser):
    """
    :type parser: ArgumentParser
    """
    parser.add_argument(
        '--key',
        type=str,
        help='The private key the csr should be generated for.',
        dest='key',
    )
    parser.add_argument(
        '-d', '--domain',
        type=str,
        dest='domains',
        nargs='+',
    )
    return parser


def patch_readme_data(usage):
    gencsr_readme = '  gencsr               Generates for the domains and a private key a csr'
    usage_lines = usage.split('\n')
    index_candidates = [
        index for index, usage_line in enumerate(usage_lines)
        if usage_line.strip().startswith('plugins') and usage_line.startswith('  ')
        ]
    index = index_candidates[0]
    usage_lines = usage_lines[:index] + [gencsr_readme] + usage_lines[index:]
    return '\n'.join(usage_lines)


def patch_readme():
    """
    patches the original readme files of letsencrypt to
    include the new gencsr command.
    """
    cli.SHORT_USAGE = patch_readme_data(cli.SHORT_USAGE)
    cli.USAGE = patch_readme_data(cli.USAGE)


def main(cli_args=sys.argv[1:]):
    """Command line argument parsing and main script execution."""
    patch_readme()

    sys.excepthook = functools.partial(_handle_exception, args=None)

    # note: arg parser internally handles --help (and exits afterwards)
    plugins = plugins_disco.PluginsRegistry.find_all()
    args = prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(args)
    zope.component.provideUtility(config)

    # Setup logging ASAP, otherwise "No handlers could be found for
    # logger ..." TODO: this should be done before plugins discovery
    for directory in config.config_dir, config.work_dir:
        le_util.make_or_verify_dir(
            directory, constants.CONFIG_DIRS_MODE, os.geteuid(),
            "--strict-permissions" in cli_args)
    # TODO: logs might contain sensitive data such as contents of the
    # private key! #525
    le_util.make_or_verify_dir(
        args.logs_dir, 0o700, os.geteuid(), "--strict-permissions" in cli_args)
    setup_logging(args, _cli_log_handler, logfile='letsencrypt.log')

    logger.debug("letsencrypt version: %s", letsencrypt.__version__)
    # do not log `args`, as it contains sensitive data (e.g. revoke --key)!
    logger.debug("Arguments: %r", cli_args)
    logger.debug("Discovered plugins: %r", plugins)

    sys.excepthook = functools.partial(_handle_exception, args=args)

    # Displayer
    if args.text_mode:
        displayer = display_util.FileDisplay(sys.stdout)
    else:
        displayer = display_util.NcursesDisplay()
    zope.component.provideUtility(displayer)

    # Reporter
    report = reporter.Reporter()
    zope.component.provideUtility(report)
    atexit.register(report.atexit_print_messages)

    if not os.geteuid() == 0:
        logger.warning(
            "Root (sudo) is required to run most of letsencrypt functionality.")
        # check must be done after arg parsing as --help should work
        # w/o root; on the other hand, e.g. "letsencrypt run
        # --authenticator dns" or "letsencrypt plugins" does not
        # require root as well
        # return (
        #    "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
        #    .format(os.linesep))

    return args.func(args, config, plugins)


if __name__ == "__main__":
    err_string = main()
    if err_string:
        logger.warn("Exiting with message %s", err_string)
    sys.exit(err_string)  # pragma: no cover
