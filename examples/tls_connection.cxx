#include "../tcp.hpp"

#define HOST "example.com"
#define PORT "443"

int main(void) {
	Tcp::Client client(HOST, PORT);
	client.setup();

	if (client.connect()) {
		std::cout << "Connected to " << HOST << " on port " << PORT << '\n';
		std::cout << "TLS Version: " << client.get_tls_version() << '\n';
		std::cout << "Cipher suite: " << client.get_tls_con_cipher() << '\n';
		std::cout << "SNI: " << client.get_tls_sni() << '\n';
		std::cout << "Certificate issuer: " << client.get_certificate_issuer()
				  << '\n';
		std::cout << "SHA256 Certificate fingerprint: "
				  << client.get_certificate_sha256_digest() << '\n';

	} else {
		std::cout << "Could not connect to host!";
		return 1;
	}
	return 0;
}
