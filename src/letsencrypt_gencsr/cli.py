# -*- encoding: utf-8 -*-

from __future__ import unicode_literals, absolute_import
import sys
from argparse import ArgumentParser

from letsencrypt.interfaces import IConfig
from zope.component import provideUtility
from letsencrypt.configuration import NamespaceConfig
from letsencrypt.cli import flag_default, config_help
from .gencsr import gencsr


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


def init_csr_parser(csr_parser):
    """
    :type csr_parser: ArgumentParser
    """
    init_key_arguments(csr_parser)
    csr_parser.add_argument(
        '-o', '--out',
        type=str,
        help='The file location the csr should be exported to.',
        dest='out',
    )
    csr_parser.set_defaults(func=gencsr)
    return csr_parser


def get_argument_parser():
    parser = ArgumentParser(
        prog='letsencrypt-csr-helper',
    )
    parser.add_argument(
        '--config-dir',
        default=flag_default('config_dir'),
        help=config_help('config_dir')
    )
    parser.add_argument(
        '--work-dir',
        default=flag_default('work_dir'),
        help=config_help('work_dir')
    )
    parser.add_argument(
        '--logs-dir',
        default=flag_default('logs_dir'),
        help='Logs directory.'
    )
    parser.add_argument(
        '--strict-permissions',
        action='store_true',
        help='Require that all configuration files are owned by the current '
             'user; only needed if your config is somewhere unsafe like /tmp/'
    )

    subparsers = parser.add_subparsers(title='Actions')
    gencsr_parser = subparsers.add_parser('gencsr', help='Generates a csr from a given key')
    init_csr_parser(gencsr_parser)
    return parser


def main():
    """
    Entry point of the application.
    """
    args = get_argument_parser().parse_args()
    result = 0
    provideUtility(args, IConfig)
    if hasattr(args, 'func'):
        result = args.func(args)
    return result or 0


if __name__ == '__main__':
    sys.exit(main())
