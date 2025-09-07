// irc_http_proxy_secure.cpp
// Qt 5.12 single-file demo: Secure IRC-driven HTTPS proxy with auth, RSA-encrypted backend posting,
// rate-limiting, ACLs. Uses OpenSSL for RSA operations and Qt network for TLS server.
// WARNING: demo only. NOT production-ready. Read comments and security notes.

// Build (Linux/macOS):
// qmake -project "QT += widgets network" && qmake && make
// You must have OpenSSL dev headers available for compilation.
// On macOS with Homebrew OpenSSL might be in /usr/local/opt/openssl or /opt/homebrew/opt/openssl@1.1

#include <QtWidgets>
#include <QtNetwork>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// -------------------- Utility: RSA decrypt with OpenSSL --------------------
static QByteArray rsaPrivateDecrypt(const QByteArray &cipher, const QString &privKeyPath, QString &errOut) {
    errOut.clear();
    FILE *fp = fopen(privKeyPath.toLocal8Bit().constData(), "rb");
    if (!fp) { errOut = "Failed to open private key file"; return QByteArray(); }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) { errOut = QString("PEM_read_RSAPrivateKey failed: %1").arg(ERR_error_string(ERR_get_error(), NULL)); return QByteArray(); }

    int keySize = RSA_size(rsa);
    QByteArray out;
    out.resize(keySize);
    int decryptedLen = RSA_private_decrypt(cipher.size(), (const unsigned char*)cipher.constData(), (unsigned char*)out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    if (decryptedLen < 0) {
        errOut = QString("RSA_private_decrypt failed: %1").arg(ERR_error_string(ERR_get_error(), NULL));
        return QByteArray();
    }
    out.resize(decryptedLen);
    return out;
}

// -------------------- MainWindow --------------------
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle("Secure IRC→HTTPS Proxy Demo (Qt 5.12)");
        QWidget *cw = new QWidget;
        setCentralWidget(cw);
        QGridLayout *g = new QGridLayout(cw);

        // IRC controls
        ircServerEdit = new QLineEdit("irc.libera.chat");
        ircPortEdit = new QLineEdit("6667");
        ircNickEdit = new QLineEdit("qtsecureproxy");
        ircChannelEdit = new QLineEdit("#testchannel");
        QPushButton *ircConnectBtn = new QPushButton("Connect IRC");

        g->addWidget(new QLabel("IRC server:"), 0, 0);
        g->addWidget(ircServerEdit, 0, 1);
        g->addWidget(new QLabel("Port:"), 0, 2);
        g->addWidget(ircPortEdit, 0, 3);
        g->addWidget(new QLabel("Nick:"), 1, 0);
        g->addWidget(ircNickEdit, 1, 1);
        g->addWidget(new QLabel("Channel:"), 1, 2);
        g->addWidget(ircChannelEdit, 1, 3);
        g->addWidget(ircConnectBtn, 0, 4, 2, 1);

        // Auth / ACL controls
        tokenEdit = new QLineEdit;
        QPushButton *addTokenBtn = new QPushButton("Add token");
        QPushButton *removeTokenBtn = new QPushButton("Remove token");
        tokensList = new QListWidget;
        tokensList->setFixedHeight(80);

        g->addWidget(new QLabel("Auth token (post in IRC as token=XYZ):"), 2, 0);
        g->addWidget(tokenEdit, 2, 1);
        g->addWidget(addTokenBtn, 2, 2);
        g->addWidget(removeTokenBtn, 2, 3);
        g->addWidget(tokensList, 3, 0, 1, 5);

        // ACL: allowed IRC nicks
        nickAclEdit = new QLineEdit;
        QPushButton *addNickBtn = new QPushButton("Add nick");
        QPushButton *removeNickBtn = new QPushButton("Remove nick");
        nickList = new QListWidget;
        nickList->setFixedHeight(80);

        g->addWidget(new QLabel("Allowed IRC nick (optional):"), 4, 0);
        g->addWidget(nickAclEdit, 4, 1);
        g->addWidget(addNickBtn, 4, 2);
        g->addWidget(removeNickBtn, 4, 3);
        g->addWidget(nickList, 5, 0, 1, 5);

        // RSA private key (for decrypting encrypted backend data)
        rsaKeyPathEdit = new QLineEdit;
        QPushButton *browseRsaBtn = new QPushButton("Load RSA privkey PEM");
        g->addWidget(new QLabel("RSA private key (PEM) path:"), 6, 0);
        g->addWidget(rsaKeyPathEdit, 6, 1);
        g->addWidget(browseRsaBtn, 6, 2);

        // HTTPS server controls (TLS cert + key)
        certPathEdit = new QLineEdit;
        keyPathEdit = new QLineEdit;
        QPushButton *browseCertBtn = new QPushButton("Load cert PEM");
        QPushButton *browseKeyBtn = new QPushButton("Load key PEM");
        httpPortEdit = new QLineEdit("8443");
        QPushButton *startHttpBtn = new QPushButton("Start HTTPS Server");

        g->addWidget(new QLabel("TLS cert (PEM):"), 7, 0);
        g->addWidget(certPathEdit, 7, 1);
        g->addWidget(browseCertBtn, 7, 2);
        g->addWidget(new QLabel("TLS key (PEM):"), 8, 0);
        g->addWidget(keyPathEdit, 8, 1);
        g->addWidget(browseKeyBtn, 8, 2);
        g->addWidget(new QLabel("HTTPS listen port:"), 9, 0);
        g->addWidget(httpPortEdit, 9, 1);
        g->addWidget(startHttpBtn, 9, 2);

        // Mapping table and rate limit
        mappingTable = new QTableWidget(0, 2);
        mappingTable->setHorizontalHeaderLabels(QStringList() << "Host" << "Backend (ip:port)");
        mappingTable->horizontalHeader()->setStretchLastSection(true);

        g->addWidget(new QLabel("Mappings (set via IRC !serve):"), 10, 0);
        g->addWidget(mappingTable, 11, 0, 1, 5);

        // Logs
        ircLog = new QTextEdit; ircLog->setReadOnly(true); ircLog->setFixedHeight(150);
        httpLog = new QTextEdit; httpLog->setReadOnly(true); httpLog->setFixedHeight(150);

        g->addWidget(new QLabel("IRC Log:"), 12, 0);
        g->addWidget(ircLog, 13, 0, 1, 5);
        g->addWidget(new QLabel("Proxy/HTTPS Log:"), 14, 0);
        g->addWidget(httpLog, 15, 0, 1, 5);

        resize(1000, 1100);

        // Network objects
        ircSocket = new QTcpSocket(this);
        server = new QTcpServer(this);
        nam = new QNetworkAccessManager(this);

        // Signals
        connect(ircConnectBtn, &QPushButton::clicked, this, &MainWindow::ircConnectClicked);
        connect(ircSocket, &QTcpSocket::readyRead, this, &MainWindow::onIrcReadyRead);
        connect(ircSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error),
                this, &MainWindow::onIrcError);
        connect(addTokenBtn, &QPushButton::clicked, this, &MainWindow::addToken);
        connect(removeTokenBtn, &QPushButton::clicked, this, &MainWindow::removeToken);
        connect(addNickBtn, &QPushButton::clicked, this, &MainWindow::addNick);
        connect(removeNickBtn, &QPushButton::clicked, this, &MainWindow::removeNick);
        connect(browseRsaBtn, &QPushButton::clicked, this, &MainWindow::browseRsaKey);
        connect(browseCertBtn, &QPushButton::clicked, this, &MainWindow::browseCert);
        connect(browseKeyBtn, &QPushButton::clicked, this, &MainWindow::browseKey);
        connect(startHttpBtn, &QPushButton::clicked, this, &MainWindow::startStopHttps);

        connect(server, &QTcpServer::newConnection, this, &MainWindow::onNewIncomingSocket);
        connect(nam, &QNetworkAccessManager::finished, this, &MainWindow::onBackendReply);

        appendIrcLog("Application started.");
    }

private slots:
    // ---------------- IRC ----------------
    void ircConnectClicked() {
        if (ircSocket->state() == QAbstractSocket::ConnectedState) {
            ircSocket->disconnectFromHost();
            appendIrcLog("Disconnecting IRC...");
            return;
        }
        QString serverAddr = ircServerEdit->text().trimmed();
        quint16 port = static_cast<quint16>(ircPortEdit->text().toUInt());
        if (serverAddr.isEmpty() || port == 0) { appendIrcLog("Invalid IRC server/port"); return; }
        appendIrcLog(QString("Connecting IRC to %1:%2").arg(serverAddr).arg(port));
        ircSocket->connectToHost(serverAddr, port);
        connect(ircSocket, &QTcpSocket::connected, this, [this]() {
            QString nick = ircNickEdit->text().trimmed(); if (nick.isEmpty()) nick = "qtsecureproxy";
            ircSendRaw(QString("NICK %1").arg(nick));
            ircSendRaw(QString("USER %1 0 * :qt secure proxy demo").arg(nick));
            QTimer::singleShot(800, this, &MainWindow::ircJoinChannel);
            appendIrcLog("Sent NICK/USER");
        });
    }

    void ircJoinChannel() {
        QString chan = ircChannelEdit->text().trimmed(); if (chan.isEmpty()) return;
        ircSendRaw(QString("JOIN %1").arg(chan));
        appendIrcLog(QString("Joining %1").arg(chan));
    }

    void onIrcReadyRead() {
        QByteArray ba = ircSocket->readAll(); ircBuf += ba;
        while (true) {
            int idx = ircBuf.indexOf("\r\n"); if (idx < 0) break;
            QByteArray line = ircBuf.left(idx); ircBuf = ircBuf.mid(idx + 2);
            QString s = QString::fromUtf8(line);
            appendIrcLog(QString("<< %1").arg(s));
            handleIrcLine(s);
        }
    }

    void handleIrcLine(const QString &line) {
        if (line.startsWith("PING ")) { QString token = line.mid(5); ircSendRaw(QString("PONG %1").arg(token)); appendIrcLog("Replied PONG"); return; }
        QRegExp rx(R"(^:([^!]+)!([^ ]+) PRIVMSG ([^ ]+) :(.*)$)");
        if (rx.indexIn(line) != -1) {
            QString nick = rx.cap(1); QString target = rx.cap(3); QString msg = rx.cap(4);
            appendIrcLog(QString("[%1] %2").arg(nick).arg(msg));
            parseIrcMessage(nick, target, msg);
        }
    }

    void parseIrcMessage(const QString &nick, const QString &target, const QString &msg) {
        // Command format:
        // !serve <host> token=TOKEN plain:host:port
        // !serve <host> token=TOKEN rsa:<base64 of RSA-encrypted backend>

        if (!msg.startsWith("!serve ")) return;
        // Basic auth: token=... present OR nick in allowed nick list
        QString lower = msg.toLower();
        QString token;
        QRegExp tRx("token=([A-Za-z0-9_\-]+)");
        if (tRx.indexIn(msg) != -1) token = tRx.cap(1);
        bool nickAllowed = allowedNicks.contains(nick, Qt::CaseInsensitive);
        bool tokenOk = (!token.isEmpty() && allowedTokens.contains(token));
        if (!nickAllowed && !tokenOk) { appendIrcLog(QString("Auth failed for %1 (token=%2)").arg(nick).arg(token)); return; }

        QString rest = msg.mid(QString("!serve ").length()).trimmed();
        QStringList parts = rest.split(QRegExp("\s+"), QString::SkipEmptyParts);
        if (parts.size() < 2) { appendIrcLog("!serve requires: host backend"); return; }
        QString host = parts[0].trimmed();
        QString backendSpec = parts[1].trimmed();

        QString backend;
        if (backendSpec.startsWith("rsa:", Qt::CaseInsensitive)) {
            if (rsaKeyPathEdit->text().isEmpty()) { appendIrcLog("No RSA private key loaded — cannot decrypt"); return; }
            QByteArray cipher = QByteArray::fromBase64(backendSpec.mid(4).toUtf8());
            QString err; QByteArray dec = rsaPrivateDecrypt(cipher, rsaKeyPathEdit->text(), err);
            if (dec.isEmpty()) { appendIrcLog(QString("RSA decrypt failed: %1").arg(err)); return; }
            backend = QString::fromUtf8(dec);
            appendIrcLog(QString("Decrypted backend to %1").arg(backend));
        } else if (backendSpec.startsWith("plain:", Qt::CaseInsensitive)) {
            backend = backendSpec.mid(6);
        } else {
            appendIrcLog("Backend must start with rsa: or plain:"); return;
        }

        if (!backend.contains(':')) { appendIrcLog("backend must be host:port"); return; }
        mappings[host] = backend;
        refreshMappingTable();
        appendIrcLog(QString("Mapping set: %1 -> %2 (by %3)").arg(host).arg(backend).arg(nick));
    }

    void ircSendRaw(const QString &raw) {
        if (ircSocket->state() != QAbstractSocket::ConnectedState) return;
        QByteArray b = raw.toUtf8(); b.append("\r\n"); ircSocket->write(b);
        appendIrcLog(QString(">> %1").arg(raw));
    }

    void onIrcError(QAbstractSocket::SocketError) { Q_UNUSED(QAbstractSocket::SocketError); appendIrcLog(QString("IRC error: %1").arg(ircSocket->errorString())); }

    // ---------------- Tokens / ACL UI ----------------
    void addToken() { QString t = tokenEdit->text().trimmed(); if (t.isEmpty()) return; if (!allowedTokens.contains(t)) { allowedTokens.insert(t); tokensList->addItem(t); tokenEdit->clear(); appendIrcLog(QString("Added token %1").arg(t)); } }
    void removeToken() { auto it = tokensList->selectedItems(); for (auto item : it) { allowedTokens.remove(item->text()); delete item; appendIrcLog(QString("Removed token %1").arg(item->text())); } }
    void addNick() { QString n = nickAclEdit->text().trimmed(); if (n.isEmpty()) return; if (!allowedNicks.contains(n)) { allowedNicks.insert(n); nickList->addItem(n); nickAclEdit->clear(); appendIrcLog(QString("Added allowed nick %1").arg(n)); } }
    void removeNick() { auto it = nickList->selectedItems(); for (auto item : it) { allowedNicks.remove(item->text()); delete item; appendIrcLog(QString("Removed allowed nick %1").arg(item->text())); } }

    void browseRsaKey() { QString f = QFileDialog::getOpenFileName(this, "Select RSA private key PEM"); if (!f.isEmpty()) rsaKeyPathEdit->setText(f); }
    void browseCert() { QString f = QFileDialog::getOpenFileName(this, "Select TLS certificate (PEM)"); if (!f.isEmpty()) certPathEdit->setText(f); }
    void browseKey() { QString f = QFileDialog::getOpenFileName(this, "Select TLS private key (PEM)"); if (!f.isEmpty()) keyPathEdit->setText(f); }

    // ---------------- HTTPS server ----------------
    void startStopHttps() {
        if (server->isListening()) { server->close(); appendHttpLog("HTTPS server stopped"); return; }
        quint16 port = static_cast<quint16>(httpPortEdit->text().toUShort()); if (port == 0) { appendHttpLog("Invalid HTTPS port"); return; }
        // Load cert/key (PEM) into QSslCertificate/QSslKey
        QString certPath = certPathEdit->text().trimmed(); QString keyPath = keyPathEdit->text().trimmed();
        if (certPath.isEmpty() || keyPath.isEmpty()) { appendHttpLog("TLS cert/key not set"); return; }
        QFile certF(certPath); if (!certF.open(QIODevice::ReadOnly)) { appendHttpLog("Failed open cert file"); return; }
        QByteArray certPem = certF.readAll(); certF.close();
        QFile keyF(keyPath); if (!keyF.open(QIODevice::ReadOnly)) { appendHttpLog("Failed open key file"); return; }
        QByteArray keyPem = keyF.readAll(); keyF.close();
        QList<QSslCertificate> certs = QSslCertificate::fromPem(certPem);
        if (certs.isEmpty()) { appendHttpLog("Failed parse certificate PEM"); return; }
        QSslCertificate cert = certs.first();
        QSslKey key(keyPem, QSsl::Rsa); if (key.isNull()) { appendHttpLog("Failed parse private key PEM"); return; }
        tlsCertificate = cert; tlsKey = key;

        if (!server->listen(QHostAddress::Any, port)) { appendHttpLog(QString("Failed to listen: %1").arg(server->errorString())); return; }
        appendHttpLog(QString("HTTPS server listening on port %1").arg(port));
    }

    void onNewIncomingSocket() {
        while (server->hasPendingConnections()) {
            QTcpSocket *tcp = server->nextPendingConnection();
            appendHttpLog(QString("Incoming connection from %1:%2").arg(tcp->peerAddress().toString()).arg(tcp->peerPort()));
            // Upgrade to QSslSocket using the socket descriptor
            qintptr sd = tcp->socketDescriptor();
            QSslSocket *ssl = new QSslSocket(this);
            if (!ssl->setSocketDescriptor(sd)) {
                appendHttpLog("Failed to set socket descriptor on QSslSocket");
                tcp->deleteLater(); delete ssl; continue;
            }
            // set cert/key
            ssl->setLocalCertificate(tlsCertificate);
            ssl->setPrivateKey(tlsKey);
            connect(ssl, &QSslSocket::encrypted, this, [this, ssl]() { appendHttpLog(QString("SSL handshake completed from %1:%2").arg(ssl->peerAddress().toString()).arg(ssl->peerPort())); });
            connect(ssl, &QSslSocket::readyRead, this, [this, ssl]() { handleSslClientReadyRead(ssl); });
            connect(ssl, &QSslSocket::disconnected, ssl, &QSslSocket::deleteLater);
            connect(ssl, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors), this, [this](const QList<QSslError> &errs){ Q_UNUSED(errs); appendHttpLog("SSL errors occurred (see system log)"); });
            // start handshake
            ssl->startServerEncryption();
            // old tcp will be cleaned up by Qt after descriptor moved
            tcp->deleteLater();
        }
    }

    // Very small HTTP parser for TLS sockets
    void handleSslClientReadyRead(QSslSocket *ssl) {
        QByteArray &buf = clientBufs[ssl]; buf.append(ssl->readAll());
        int idx = buf.indexOf("\r\n\r\n"); if (idx < 0) return; // wait for headers
        QByteArray headerBlock = buf.left(idx + 4);
        QString headerText = QString::fromUtf8(headerBlock);
        QStringList lines = headerText.split("\r\n", QString::SkipEmptyParts);
        if (lines.isEmpty()) { ssl->disconnectFromHost(); return; }
        QString requestLine = lines[0]; QStringList reqParts = requestLine.split(' ');
        if (reqParts.size() < 2) { ssl->disconnectFromHost(); return; }
        QString method = reqParts[0]; QString path = reqParts[1];
        appendHttpLog(QString("HTTPS request: %1 %2 from %3").arg(method).arg(path).arg(ssl->peerAddress().toString()));

        // simple path: /host/rest
        if (!path.startsWith('/')) { sendHttpSimpleSsl(ssl, 400, "Bad Request", "Path must start with /"); return; }
        QString pathNoLead = path.mid(1);
        int slashPos = pathNoLead.indexOf('/'); QString hostPart; QString restPath;
        if (slashPos == -1) { hostPart = pathNoLead; restPath = "/"; } else { hostPart = pathNoLead.left(slashPos); restPath = pathNoLead.mid(slashPos); }
        if (!mappings.contains(hostPart)) { sendHttpSimpleSsl(ssl, 502, "Bad Gateway", QString("No mapping for host %1").arg(hostPart)); return; }
        QString backend = mappings[hostPart];
        QString backendUrl = QString("http://%1%2").arg(backend).arg(restPath);
        appendHttpLog(QString("Proxying to %1").arg(backendUrl));

        // Rate limiting per IP
        QHostAddress clientIp = ssl->peerAddress();
        if (!checkRateLimit(clientIp)) { sendHttpSimpleSsl(ssl, 429, "Too Many Requests", "Rate limit exceeded"); return; }

        QNetworkRequest req(QUrl(backendUrl)); req.setRawHeader("Host", hostPart.toUtf8());
        QNetworkReply *reply = nam->get(req);
        replyToSslClient[reply] = ssl;
        clientBufs.remove(ssl);
    }

    void onBackendReply(QNetworkReply *reply) {
        QSslSocket *ssl = replyToSslClient.value(reply, nullptr);
        replyToSslClient.remove(reply);
        if (!ssl) { appendHttpLog("No SSL client for backend reply"); reply->deleteLater(); return; }
        if (reply->error() != QNetworkReply::NoError) { appendHttpLog(QString("Backend fetch error: %1").arg(reply->errorString())); sendHttpSimpleSsl(ssl, 502, "Bad Gateway", QString("Backend error: %1").arg(reply->errorString())); reply->deleteLater(); return; }
        int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(); QByteArray body = reply->readAll();
        QByteArray resp;
        resp.append(QString("HTTP/1.1 %1 OK\r\n").arg(status));
        QVariant ct = reply->header(QNetworkRequest::ContentTypeHeader);
        if (ct.isValid()) resp.append(QString("Content-Type: %1\r\n").arg(ct.toString()));
        resp.append(QString("Content-Length: %1\r\n").arg(body.size()));
        resp.append("Connection: close\r\n\r\n");
        resp.append(body);
        ssl->write(resp); ssl->flush(); ssl->disconnectFromHost(); appendHttpLog(QString("Proxied %1 bytes to %2").arg(body.size()).arg(ssl->peerAddress().toString()));
        reply->deleteLater();
    }

    // ---------------- Rate limiting ----------------
    bool checkRateLimit(const QHostAddress &ip) {
        const int WINDOW_MS = 60000; // 1 minute
        const int MAX_REQUESTS = 60; // per window
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        auto &st = rateState[ip.toString()];
        if (now - st.windowStart > WINDOW_MS) { st.windowStart = now; st.count = 0; }
        st.count += 1;
        return st.count <= MAX_REQUESTS;
    }

    // ---------------- Helpers ----------------
    void sendHttpSimpleSsl(QSslSocket *ssl, int code, const QString &reason, const QString &body) {
        QByteArray resp; resp.append(QString("HTTP/1.1 %1 %2\r\n").arg(code).arg(reason)); resp.append(QString("Content-Length: %1\r\n").arg(body.toUtf8().size())); resp.append("Connection: close\r\n"); resp.append("Content-Type: text/plain\r\n\r\n"); resp.append(body.toUtf8()); ssl->write(resp); ssl->flush(); ssl->disconnectFromHost();
    }

    void sendHttpSimple(QTcpSocket *cli, int code, const QString &reason, const QString &body) { Q_UNUSED(cli); Q_UNUSED(code); Q_UNUSED(reason); Q_UNUSED(body); }

    void refreshMappingTable() {
        mappingTable->setRowCount(0); int r=0; for (auto it = mappings.begin(); it != mappings.end(); ++it) {
            mappingTable->insertRow(r); mappingTable->setItem(r,0,new QTableWidgetItem(it.key())); mappingTable->setItem(r,1,new QTableWidgetItem(it.value())); ++r; }
    }

    void appendIrcLog(const QString &s) { QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"); ircLog->append(QString("[%1] %2").arg(ts).arg(s)); }
    void appendHttpLog(const QString &s) { QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"); httpLog->append(QString("[%1] %2").arg(ts).arg(s)); }

    // ---------------- UI / state ----------------
    QLineEdit *ircServerEdit; QLineEdit *ircPortEdit; QLineEdit *ircNickEdit; QLineEdit *ircChannelEdit;
    QLineEdit *tokenEdit; QListWidget *tokensList; QSet<QString> allowedTokens;
    QLineEdit *nickAclEdit; QListWidget *nickList; QSet<QString> allowedNicks;
    QLineEdit *rsaKeyPathEdit;
    QLineEdit *certPathEdit; QLineEdit *keyPathEdit; QLineEdit *httpPortEdit;
    QTableWidget *mappingTable;
    QTextEdit *ircLog; QTextEdit *httpLog;

    // network
    QTcpSocket *ircSocket; QTcpServer *server; QNetworkAccessManager *nam;
    QByteArray ircBuf;
    QMap<QString, QString> mappings;
    QHash<QNetworkReply*, QSslSocket*> replyToSslClient;
    QHash<QSslSocket*, QByteArray> clientBufs; // reuse for SSL sockets

    QSslCertificate tlsCertificate; QSslKey tlsKey;

    struct RateState { qint64 windowStart = 0; int count = 0; };
    QHash<QString, RateState> rateState;

};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow w; w.show();
    return app.exec();
}

#include "irc_http_proxy_secure.moc"
