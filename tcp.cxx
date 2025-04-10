#include "tcp.hpp"

namespace Tcp {
Client::Client(const std::string &host, const std::string &port)
    : _host(host), _port(port), _is_ssl(true) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

Client::Client(const std::string &host, const std::string &port, bool ssl)
    : _host(host), _port(port), _is_ssl(ssl) {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

Client::~Client() { _cleanup(); }

void Client::reset() {
  _cleanup();
  *this = Tcp::Client(_host, _port, _is_ssl);
}

const std::string Client::get_tls_sni() const {
  if (!_connected || !_ssl)
    return "";
  return SSL_get_servername(_ssl, TLSEXT_NAMETYPE_host_name);
}

const std::string Client::get_tls_version() const {
  if (!_connected || !_ssl)
    return "";
  return SSL_get_version(_ssl);
}

const std::string Client::get_tls_con_cipher() const {
  if (!_connected || !_ssl)
    return "";
  return SSL_get_cipher(_ssl);
}

const std::string Client::get_tls_config_ciphers() const {
  std::stringstream ss;
  if (_ssl_ctx) {
    auto ciphers = SSL_CTX_get_ciphers(_ssl_ctx);
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
      const char *cipherName = SSL_CIPHER_get_name(cipher);
      ss << cipherName << ':';
    }
  }
  return ss.str();
}

const X509 *Client::get_raw_certificate() const {
  if (_server_cert)
    return _server_cert;
  return nullptr;
}

const std::string Client::get_certificate_issuer() const {
  if (!_server_cert)
    return "";

  // assuming this null terminates else use bio api
  char *subject = X509_NAME_oneline(X509_get_subject_name(_server_cert), 0, 0);
  return std::string(subject);
}

const std::string Client::get_certificate_sha256_digest() const {
  if (!_server_cert)
    return "";

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;

  if (!X509_digest(_server_cert, EVP_sha256(), digest, &digest_len))
    return "";

  std::ostringstream oss;
  for (unsigned int i = 0; i < digest_len; ++i) {
    if (i > 0)
      oss << ":";
    oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(digest[i]);
  }
  return oss.str();
}

bool Client::_open_ssl_setup() {

  _ssl_ctx = SSL_CTX_new(TLS_client_method());

  if (!_ssl_ctx)
    return false;

  if (_verify)
    SSL_CTX_set_verify(_ssl_ctx, SSL_VERIFY_PEER, nullptr);
  else
    SSL_CTX_set_verify(_ssl_ctx, SSL_VERIFY_NONE, nullptr);

  if (_disable_insecure)
    SSL_CTX_set_options(_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                      SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

  SSL_CTX_set_min_proto_version(_ssl_ctx, _min_tls_version);
  SSL_CTX_set_max_proto_version(_ssl_ctx, _max_tls_version);

  if (!_alpn_protocols.empty())
    SSL_CTX_set_alpn_protos(
        _ssl_ctx,
        reinterpret_cast<const unsigned char *>(_alpn_protocols.data()),
        _alpn_protocols.size());

  int res = _set_cert_store();

  if (!_ciphers.empty())
    res = SSL_CTX_set_cipher_list(_ssl_ctx, _ciphers.c_str());

  return res == 1;
}

void Client::set_tls_min_version(int version) { _min_tls_version = version; }
void Client::set_tls_max_version(int version) { _max_tls_version = version; }

void Client::set_verify(bool verify) {
  if (_setup)
    return;
  _verify = verify;
}

void Client::set_verify_hostname(bool verify) {
  if (_setup)
    return;
  _verify_hostname = verify;
}

void Client::set_alpn_protocols(const std::vector<unsigned char> &protocols) {
  if (_setup)
    return;
  _alpn_protocols = protocols;
}

void Client::set_disable_insecure_protocols(bool disable) {
  if (_setup)
    return;
  _disable_insecure = disable;
}

void Client::set_verify_locations(
    const std::pair<std::string, std::string> &path) {
  if (_setup)
    return;
  _paths = path;
}

void Client::set_cipher_suites(const std::string &ciphers) {
  if (_setup)
    return;
  _ciphers = ciphers;
}

bool Client::setup() {
#if defined(_WIN32) || defined(_WIN64)
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    WSACleanup();
    return false;
  }
#endif
  if (_setup)
    return false;

  if (_is_ssl && !_open_ssl_setup())
    return false;

  if (!_resolve_domain_name()) {
    freeaddrinfo(_ll_dns);
    return false;
  }

  for (_final_addr = _ll_dns; _final_addr != nullptr;
       _final_addr = _final_addr->ai_next) {
    _c_socket = socket(_final_addr->ai_family, _final_addr->ai_socktype,
                       _final_addr->ai_protocol);

    if (_c_socket != -1)
      break;
  }

  if (_c_socket == -1) {
    _setup = false;
    return false;
  }

  _setup = true;
  return true;
}

bool Client::connect() {
  TCP_ASSERT(_setup, "Forgot to call setup before connect?");

  if (_c_socket == -1 && _final_addr) {
    // cached dns res which is likely gonna be correct
    _c_socket = socket(_final_addr->ai_family, _final_addr->ai_socktype,
                       _final_addr->ai_protocol);
  }

  if (!_ssl && _is_ssl)
    _ssl = SSL_new(_ssl_ctx);
  if (_ssl && SSL_set_fd(_ssl, _c_socket) != 1) {
    _cleanup();
    CLOSE_SOCKET(_c_socket);
    _c_socket = -1;
    return false;
  }

  if (_ssl && SSL_set_tlsext_host_name(_ssl, _host.c_str()) != 1) {
    _cleanup();
    CLOSE_SOCKET(_c_socket);
    _c_socket = -1;
    return false;
  }

  if (_ssl && _verify_hostname) {
    SSL_set1_host(_ssl, _host.c_str());
  }

#if defined(__APPLE__) || defined(__linux__)
  if (::connect(_c_socket, _final_addr->ai_addr, _final_addr->ai_addrlen) ==
      -1) {
    _cleanup();
    return false;
  }
#elif defined(_WIN32) || defined(_WIN64)
  if (::connect(_c_socket, (SOCKADDR *)&sAddr, sizeof(sAddr)) == SOCKET_ERROR) {
    _cleanup();
    return false;
  }
#endif

  if (_is_ssl && SSL_connect(_ssl) != 1)
    return false;
  _connected = true;

  // gets leaf certificate not entire chain
  if (_is_ssl && _ssl)
    _server_cert = SSL_get_peer_certificate(_ssl);
  return true;
}

void Client::disconnect() {
  if (_connected && _ssl)
    SSL_shutdown(_ssl);

  if (_connected)
    shutdown(_c_socket, SHUT_RDWR);

  _connected = false;

  if (_ssl) {
    SSL_free(_ssl);
    _ssl = nullptr;
  }

  if (_c_socket != -1) {
    CLOSE_SOCKET(_c_socket);
    _c_socket = -1;
  }
}

bool Client::is_connected() {
#if defined(_WIN32) || defined(_WIN64)
  return false;
#endif

  if (!_connected)
    return false;

  int socket = _is_ssl && _ssl ? SSL_get_fd(_ssl) : _c_socket;

  if (socket < 0) {
    _connected = false;
    return false;
  }

  struct pollfd poll_fd = {.fd = socket, .events = POLLIN, .revents = 0};

  int poll_r = poll(&poll_fd, 1, 0);

  if (poll_r < 0) {
    disconnect();
    return false;
  }

  // edge case here?
  if (poll_r == 0)
    return true;

  if (poll_fd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
    disconnect();
    return false;
  }

  if (poll_fd.revents & POLLIN) {
    uint8_t byte;
    int read = ::recv(socket, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    if (read == 0) {
      disconnect();
      return false;
    }

    if (read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      _connected = false;
      disconnect();
      return false;
    }
  }

  return true;
}

int Client::send(const uint8_t *data, size_t size) {
  int ret = -1;
  if (!_connected)
    return ret;
  if (_is_ssl && _ssl)
    return SSL_write(_ssl, data, size);
  return write(_c_socket, data, size);
}

int Client::send_all(const std::vector<uint8_t> &data) {
  int ret = -1;
  if (!_connected)
    return ret;

  size_t total = 0;
  size_t left = data.size();

  size_t sent;
  while (total < data.size()) {
    if (_is_ssl && _ssl)
      sent = SSL_write(_ssl, data.data() + total, left);
    else
      sent = write(_c_socket, data.data() + total, left);

    if (sent <= 0)
      return -1;

    if (left == 0)
      break;

    total += sent;
    left -= sent;
  }
  return total;
}

std::vector<uint8_t> Client::recv(size_t to_recv, int flags) {
  if (!_connected || to_recv == 0)
    return {};
  std::vector<uint8_t> ret(to_recv);
  int recv;
  if (_is_ssl && _ssl)
    recv = SSL_read(_ssl, ret.data(), to_recv);
  else
    recv = ::recv(_c_socket, ret.data(), to_recv, flags);

  if (recv == 0) {
    disconnect();
    return {};
  }
  ret.resize(recv);
  return ret;
}

std::vector<uint8_t> Client::recv_all(size_t chunk_size, int poll_ms) {
  if (!_connected)
    return {};

  std::vector<uint8_t> ret;

  int socket = _is_ssl && _ssl ? SSL_get_fd(_ssl) : _c_socket;

  struct pollfd poll_fd = {.fd = socket, .events = POLLIN, .revents = 0};

  while (true) {
    std::vector<uint8_t> temp(chunk_size);
    int poll_r = poll(&poll_fd, 1, poll_ms);

    if (poll_r <= 0 || !(poll_fd.revents & POLLIN)) {
      return ret;
    }

    int read = 0;
    if (_is_ssl && _ssl)
      read = SSL_read(_ssl, temp.data(), temp.size());
    else
      read = ::recv(_c_socket, temp.data(), temp.size(), 0);

    if (read == 0) {
      return ret;
    }
    ret.insert(ret.end(), temp.begin(), temp.begin() + read);
  }
  return ret;
}

bool Client::_resolve_domain_name() {
  addrinfo hints;
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  return getaddrinfo(_host.c_str(), _port.c_str(), &hints, &_ll_dns) == 0;
}

bool Client::_set_cert_store() {
  if (!_paths.first.empty() || !_paths.second.empty()) {
    int result = SSL_CTX_load_verify_locations(_ssl_ctx, _paths.first.c_str(),
                                               _paths.second.c_str());
    if (result != 1) {
      _cleanup();
      return false;
    }
    return true;
  }

  // no way of knowing if this succeed
#if defined(_WIN32) || defined(_WIN64)
  SSL_CTX_set_cert_store(sslCtx, store);
#elif defined(__APPLE__) || defined(__linux__)
  if (SSL_CTX_set_default_verify_paths(_ssl_ctx) != 1) {
    _cleanup();
    return false;
  }
  return true;
#endif
}

void Client::_cleanup() {
  if (_connected && _ssl)
    SSL_shutdown(_ssl);

  if (_connected)
    shutdown(_c_socket, SHUT_RDWR);

  _connected = false;
  _setup = false;

  if (_ssl) {
    SSL_free(_ssl);
    _ssl = nullptr;
  }

  if (_ssl_ctx) {
    SSL_CTX_free(_ssl_ctx);
    _ssl_ctx = nullptr;
  }

  if (_c_socket != -1) {
    CLOSE_SOCKET(_c_socket);
    _c_socket = -1;
  }

  if (_ll_dns) {
    freeaddrinfo(_ll_dns);
    _ll_dns = nullptr;
    _final_addr = nullptr;
  }
}

} // namespace Tcp
