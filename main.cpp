#include <cxxopts.hpp>

#include <openssl/conf.h>
#include <openssl/ssl.h>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
  cxxopts::Options options("tls_client", "TLS client as part of YSDA practice assignment");
  options.add_options()
    ("host", "Hostname to be dialed", cxxopts::value<std::string>())
    ("resource", "Resource to be requested", cxxopts::value<std::string>())
    ("v,tls-version", "TLS protocol version, available values: 1.2, 1.3", cxxopts::value<std::string>()->default_value("1.2"))
    ("c,ciphersuite", "Supported ciphersuites", cxxopts::value<std::vector<std::string>>())
    ("h,help", "Print usage")
    ;

  options.parse_positional({"host", "resource"});
  auto args = options.parse(argc, argv);

  if (args.count("help")) {
    options.positional_help("<host> <resource>");
    std::cout << options.help() << std::endl;
    exit(0);
  }

  return 0;
}
