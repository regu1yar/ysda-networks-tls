#include <cxxopts.hpp>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

constexpr std::string_view HTTPS_PORT = "443";

int main(int argc, char** argv) {
  cxxopts::Options options("tls_client", "TLS client as part of YSDA practice assignment");
  options.add_options()
    ("host", "Hostname to be dialed", cxxopts::value<std::string>())
    ("resource", "Resource to be requested", cxxopts::value<std::string>())
    ("v,tls-version", "TLS protocol version, available values: 1.2, 1.3", cxxopts::value<std::string>()->default_value("1.2"))
    ("c,ciphers", "Supported ciphersuites", cxxopts::value<std::vector<std::string>>())
    ("h,help", "Print usage")
    ;

  options.parse_positional({"host", "resource"});
  auto args = options.parse(argc, argv);

  if (args.count("help")) {
    options.positional_help("<host> <resource>");
    std::cout << options.help() << std::endl;
    exit(0);
  }

  const auto tls_version = args["tls-version"].as<std::string>();
  const auto hostname = args["host"].as<std::string>();
  const auto ciphers_args = args["ciphers"].as<std::vector<std::string>>();
  const auto resource = args["resource"].as<std::string>();

  const SSL_METHOD* method = TLS_client_method();
  if (!method) {
    std::cerr << "Filed to create tls method" << std::endl;
    exit(1);
  }

  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) {
    std::cerr << "Failed to create SSL_CTX" << std::endl;
    exit(1);
  }

  if (tls_version == "1.2") {
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) {
      std::cerr << "Failed to set max TLS version to 1.2" << std::endl;
      exit(1);
    }
  } else if (tls_version == "1.3") {
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
      std::cerr << "Failed to set min TLS version to 1.3" << std::endl;
      exit(1);
    }
  } else {
    std::cerr << "Unsupported TLS version: " << tls_version << std::endl;
    exit(2);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);
  // if (SSL_CTX_load_verify_file(ctx, "/private/etc/ssl/cert.pem") != 1) {
  //   std::cerr << "Failed to set verify paths" << std::endl;
  //   exit(1);
  // }
  if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
    std::cerr << "Failed to set verify paths" << std::endl;
    exit(1);
  }

  BIO* web = BIO_new_ssl_connect(ctx);
  if (!web) {
    std::cerr << "Failed to create connection BIO" << std::endl;
    exit(1);
  }

  std::stringstream addr_builder;
  addr_builder << hostname << ':' << HTTPS_PORT;
  const auto addr = addr_builder.str();
  BIO_set_conn_hostname(web, addr.c_str());

  SSL *ssl = NULL;
  if (BIO_get_ssl(web, &ssl) != 1) {
    std::cerr << "Failed to retrieve SSL pointer" << std::endl;
    exit(1);
  }

  std::stringstream ciphersuites_string_builder;
  for (const auto& cipher : ciphers_args) {
    ciphersuites_string_builder << cipher << ':';
  }
  auto ciphers = ciphersuites_string_builder.str();
  ciphers = ciphers.substr(0, ciphers.size() - 1);

  if (tls_version == "1.2") {
    if (SSL_set_cipher_list(ssl, ciphers.c_str()) != 1) {
      std::cerr << "Failed to set ciphers list: " << ciphers << std::endl;
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  } else if (tls_version == "1.3") {
    if (SSL_set_ciphersuites(ssl, ciphers.c_str()) != 1) {
      std::cerr << "Failed to set ciphersuites: " << ciphers << std::endl;
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  } else {
    std::cerr << "Unsupported TLS version: " << tls_version << std::endl;
    exit(2);
  }

  BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (!out) {
    std::cerr << "Failed to create stdout BIO" << std::endl;
    exit(1);
  }

  if (BIO_do_connect(web) != 1) {
    std::cerr << "Failed to connect to host " << hostname << std::endl;
    ERR_print_errors_fp(stderr);
    goto finish;
  }

  if (!BIO_do_handshake(web)) {
    std::cerr << "Failed to perform TLS handshake with " << hostname << std::endl;
    goto finish;
  }

  if (X509* cert = SSL_get_peer_certificate(ssl)) {
    X509_free(cert);
  } else {
    std::cerr << "Failed to get server certificate" << std::endl;
    goto finish;
  }

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    std::cerr << "Failed to verify certificates chain" << std::endl;
    goto finish;
  }

  BIO_puts(web, ("GET " + resource + " HTTP/1.1\r\n"
                 "Host: " + hostname + "\r\n"
                 "Connection: close\r\n\r\n").c_str());
  BIO_puts(out, "\n");

  {
    int len = 0;
    do
    {
      char buff[1536] = {};
      len = BIO_read(web, buff, sizeof(buff));
                
      if (len > 0) {
        BIO_write(out, buff, len);
      }

    } while (len > 0 || BIO_should_retry(web));
  }

finish:
  if (out) {
    BIO_free(out);
  }

  if (web) {
    BIO_free_all(web);
  }

  if (ctx) {
    SSL_CTX_free(ctx);
  }

  return 0;
}
