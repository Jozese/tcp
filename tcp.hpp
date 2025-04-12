#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <sstream>
#include <vector>

#if defined(__APPLE__) || defined(__linux__)

#	include <arpa/inet.h>
#	include <fcntl.h>
#	include <netdb.h>
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#	include <poll.h>
#	include <sys/socket.h>
#	include <unistd.h>

#elif defined(_WIN32) || defined(_WIN64)
#	include <ip2string.h>
#	include <wincrypt.h>
#	include <winsock2.h>
#	include <ws2tcpip.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
#	include <windows.h>
#	define DEBUG_BREAK() __debugbreak()
#else
#	include <csignal>
#	define DEBUG_BREAK() raise(SIGTRAP)
#endif

#define TCP_ASSERT(cond, msg)                               \
	do {                                                    \
		if (!(cond)) {                                      \
			std::cerr << "ASSERT FAILED: " << #cond << "\n" \
					  << msg << "\n";                       \
			DEBUG_BREAK();                                  \
			std::abort();                                   \
		}                                                   \
	} while (0)

#if defined(_WIN32) || defined(_WIN64)
#	define CLOSE_SOCKET(s) closesocket((s))
#else
#	define CLOSE_SOCKET(s) close((s))
#endif

namespace Tcp {
class Client {

  public:
	Client(const std::string& host, const std::string& port);
	Client(const std::string& host, const std::string& port, bool ssl);
	~Client();

  public:
	Client() = delete;

  public:
	void reset();

  public:
	bool connect();
	void disconnect();
	bool is_connected();

  public:
	// instant send/recv
	int send(const uint8_t* data, size_t size);
	std::vector<uint8_t> recv(size_t to_recv, int flags);

	int send_all(const std::vector<uint8_t>& data);

	// tries to recv all data available polling at poll_ms rate till no more data
	// or server closes
	std::vector<uint8_t> recv_all(size_t chunk_size = 4096, int poll_ms = 1000);

  public:
	const std::string get_tls_version() const;
	const std::string get_tls_config_ciphers() const;
	const std::string get_tls_con_cipher() const;
	const std::string get_tls_sni() const;

	const X509* get_raw_certificate() const;
	const std::string get_certificate_issuer() const;
	const std::string get_certificate_sha256_digest() const;

  public:
	bool setup();

	// these config functions should be called before setup and connect

	// full chain verification, on by default
	void set_verify(bool verify);

	// openssl verification doesnt verify that hostname matches CN or in SANs
	void set_verify_hostname(bool verify);

	// cert bundle, store path, or both
	void set_verify_locations(const std::pair<std::string, std::string>& path);

	// sslv2 sslv3 tls1.0-1.1
	void set_disable_insecure_protocols(bool disable);

	// example: {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
	void set_alpn_protocols(const std::vector<unsigned char>& protocols);

	// check openssl cipher suite list format
	void set_cipher_suites(const std::string& ciphers);

	void set_tls_min_version(int version);
	void set_tls_max_version(int version);

  private:
	bool _resolve_domain_name();

  private:
	bool _open_ssl_setup();
	bool _set_cert_store();
	void _cleanup();

	// cert stuff for win
  private:
#if defined(_WIN32) || defined(_WIN64)
	char ipv4[INET_ADDRSTRLEN];
	WSADATA wsaData;

	X509_STORE* store = nullptr;
	bool storeSet = false;
#endif

  private:
	std::string _host;
	std::string _port;
	addrinfo* _ll_dns = nullptr;
	addrinfo* _final_addr = nullptr;

  private:
	// change to bitfield later
	bool _is_ssl = true;
	bool _connected = false;
	bool _setup = false;
	bool _verify = true;
	bool _disable_insecure = true;
	bool _verify_hostname = true;

	std::pair<std::string, std::string> _paths;
	std::vector<uint8_t> _alpn_protocols;
	std::string _ciphers;

	int _min_tls_version = TLS1_2_VERSION;
	int _max_tls_version = TLS1_3_VERSION;

  private:
	int _c_socket = -1;

	SSL_CTX* _ssl_ctx = nullptr;
	SSL* _ssl = nullptr;

	X509* _server_cert = nullptr;
};
}; // namespace Tcp
