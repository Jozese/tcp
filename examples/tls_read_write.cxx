#include "../tcp.hpp"
#include <cstdint>
#include <string_view>
#include <unistd.h>

#define HOST "www.google.com"
#define PORT "443"

int main(void) {

  std::string_view http_request = "GET / HTTP/1.1\r\n"
                                  "Host: www.google.com\r\n"
                                  "User-Agent: tcp\r\n"
                                  "\r\n";

  Tcp::Client client(HOST, PORT);
  client.setup();

  if (client.connect()) {

    // send and recv_all

    std::cout << "Connected to " << HOST << " on port " << PORT << '\n';
    std::cout << "Sent: "
              << client.send(
                     reinterpret_cast<const uint8_t *>(http_request.data()),
                     http_request.size())
              << "\n";
    while (client.is_connected()) {
      std::cout << client.is_connected() << std::endl;
      auto all = client.recv_all();
      std::cout.write(reinterpret_cast<const char *>(all.data()), all.size());
    }
  } else {
    std::cout << "Could not connect to host!";
    return 1;
  }
  return 0;
}
