# -*- encoding: utf-8 -*-

from __future__ import absolute_import

from setuptools import setup, find_packages

requires = [
    'letsencrypt',
]

VERSION = '0.1.0'

setup(
    name='letsencrypt_gencsr',
    version=VERSION,
    description='Command line utility to generate a csr for letsencrypt from a preexisting key',
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 2 :: Only",
        "Programming Language :: Python :: 2.7",
        "Topic :: System :: Networking",
    ],
    author='Christoph Brand',
    author_email='christoph@brand.rest',
    keywords=['network', 'letsencrypt', 'ssl'],
    packages=find_packages('src'),  # include all packages under src
    package_dir={'': 'src'},  # tell distutils packages are under src
    namespace_packages=[],
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    url='https://github.com/cbrand/letsencrypt_gencsr',
    download_url='https://github.com/cbrand/letsencrypt_gencsr/tarball/%s' % VERSION,
    entry_points={
        'console_scripts': [
            'letsencrypt-gencsr-helper=letsencrypt_gencsr.cli:main'
        ]
    },
)
