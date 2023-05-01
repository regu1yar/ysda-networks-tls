# YSDA TLS client

C++-implementation for primitive TLS-client using OpenSSL library.

## Quick start

For your convenience the Dockerfile with all dependencies is provided. To build an executable follow the steps:

1. Build the Docker image:
```bash
docker build -t ysda-networks-tls-env .
```
2. Run the container:
```bash
docker run --rm -it --name ysda-networks-tls ysda-networks-tls-env /bin/bash
```
3. Copy project sources from separate terminal into container:
```bash
docker cp . ysda-networks-tls:/home/ysda-networks-tls
```
4. Enter the project directory and create a `build` directiry:
```bash
cd /home/ysda-networks-tls && mkdir build && cd build
```
5. Build an executable:
```bash
cmake .. && make
```

Use `--help` option to get an info on usage:
```bash
$ ./tls_client --help
TLS client as part of YSDA practice assignment
Usage:
  tls_client [OPTION...] <host> <resource>

  -v, --tls-version arg  TLS protocol version, available values: 1.2, 1.3
                         (default: 1.2)
  -c, --ciphers arg      Supported ciphersuites
      --key-stdout       Print keys to standard output
  -k, --keylog arg       Filename to print keylog to
  -h, --help             Print usage
```

### TLS 1.2 client example

```bash
./tls_client example.org / -v 1.2 --ciphers TLSv1.2
```

### TLS 1.3 client example

```bash
./tls_client example.org / -v 1.3 --ciphers TLS_AES_256_GCM_SHA384
```

## Technologies stack

- C++
- cmake - as build system
- [OpenSSL](https://www.openssl.org) 1.1 - for TLS interface
- [cxxopts](https://github.com/jarro2783/cxxopts) - cli arguments parser
- docker
