// Secure IRC-driven HTTPS proxy with auth, RSA-encrypted backend posting,
// rate-limiting, ACLs. Uses OpenSSL for RSA operations and Qt network for TLS server.

basically it watches irc for a server request then reverse handshakes on the webserver port needed then they can connect normally.
