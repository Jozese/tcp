#include "../tcp.hpp"

#define HOST "example.com"
#define PORT "443"

int main(void) {
  Tcp::Client client(HOST, PORT);
  client.set_cipher_suites("HIGH:!aNULL:!MD5");
  client.set_tls_min_version(TLS1_1_VERSION);
  client.set_tls_max_version(TLS1_2_VERSION);

  client.setup();

  if (client.connect()) {
    std::cout << "Connected to " << HOST << " on port " << PORT << '\n';
    std::cout << "Ciphers used in handshake: "
              << client.get_tls_config_ciphers() << '\n';
    std::cout << "Cipher chosen: " << client.get_tls_con_cipher() << '\n';
    std::cout << "Protocol version: " << client.get_tls_version() << '\n';

  } else {
    std::cout << "Could not connect to host!";
    return 1;
  }

  client.reset(); // default config
  client.setup();

  if (client.connect()) {
    std::cout << "Connected to " << HOST << " on port " << PORT << '\n';
    std::cout << "Ciphers used in handshake: "
              << client.get_tls_config_ciphers() << '\n';
    std::cout << "Cipher chosen: " << client.get_tls_con_cipher() << '\n';
    std::cout << "Protocol version: " << client.get_tls_version() << '\n';

  } else {
    std::cout << "Could not connect to host!";
    return 1;
  }

  return 0;
}
