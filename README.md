# Letsencrypt GenCSR #

A very fin wrapper around letsencrypt which allows the construction of a CSR which is
compatible with the letsencrypt toolchain.

Use this, if you don't want to generate new private keys every time when requesting
letsencrypt certificates. Even though this is generally a good security practice it might
be problematic when using public key pinning.

## Installation ##

```
pip install letsencrypt_gencsr
```

## Usage ##

```
letsencrypt-gencsr-helper gencsr --key privkey.pem -d my.awesome.domain.net awesome.domain.net domain.net -o request.csr
```

This generates form the given key "privkey.pem" and the domains "my.awesome.domain.net", "awesome.domain.net" and
"domain.net" a CSR file (in request.csr) compatible with letsencrypt which can be passed to the toolchain through
the --csr flag:

```
letsencrypt certonly --csr request.csr --webroot --renew-by-default --agree-tos -w /var/www
```

## Letsencrypt proxy ##

As of Version 0.2.0 the `letsencrypt-gencsr-helper` acts as a proxy of the `letsencrypt` cli interface and has the
same commands.

This is done to support the additional `--private-key` parameter. It allows to feed a pre defined private key to the
`certonly` certificate request:

```
letsencrypt-gencsr-helper certonly --private-key privatekey.pem --webroot -w /var/www -d example.com
```

Of course the same functionality also works with the `run` command.

## License ##

The application is licensed under the [MIT license](http://opensource.org/licenses/MIT). The used
letsencrypt library is licensed under the [Apache 2.0 license](http://opensource.org/licenses/apache-2.0).
