// irc_http_proxy_demo.cpp
// Qt 5.12 single-file demo: IRC-driven HTTP proxy mapping
// Build: qmake (with "QT += widgets network") && make

#include <QtWidgets>
#include <QtNetwork>

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle("IRC → HTTP proxy demo (Qt 5.12 single file)");

        // UI
        QWidget *cw = new QWidget;
        setCentralWidget(cw);
        QGridLayout *g = new QGridLayout(cw);

        // IRC controls
        ircServerEdit = new QLineEdit("irc.libera.chat");
        ircPortEdit = new QLineEdit("6667");
        ircNickEdit = new QLineEdit("qtproxydemo");
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

        // Mapping table
        mappingTable = new QTableWidget(0, 2);
        mappingTable->setHorizontalHeaderLabels(QStringList() << "Host" << "Backend (ip:port)");
        mappingTable->horizontalHeader()->setStretchLastSection(true);

        // HTTP server controls
        httpPortEdit = new QLineEdit("8080");
        QPushButton *httpStartBtn = new QPushButton("Start HTTP Server");

        g->addWidget(new QLabel("HTTP listen port:"), 2, 0);
        g->addWidget(httpPortEdit, 2, 1);
        g->addWidget(httpStartBtn, 2, 2);

        // Logs
        ircLog = new QTextEdit;
        ircLog->setReadOnly(true);
        httpLog = new QTextEdit;
        httpLog->setReadOnly(true);

        QSplitter *split = new QSplitter(Qt::Vertical);
        QWidget *top = new QWidget;
        QVBoxLayout *tv = new QVBoxLayout(top);
        tv->addWidget(new QLabel("IRC Log:"));
        tv->addWidget(ircLog);
        tv->addWidget(new QLabel("Mappings:"));
        tv->addWidget(mappingTable);
        split->addWidget(top);

        QWidget *bottom = new QWidget;
        QVBoxLayout *bv = new QVBoxLayout(bottom);
        bv->addWidget(new QLabel("HTTP / Proxy Log:"));
        bv->addWidget(httpLog);
        split->addWidget(bottom);

        g->addWidget(split, 3, 0, 1, 5);

        resize(900, 700);

        // Networking objects
        ircSocket = new QTcpSocket(this);
        httpServer = new QTcpServer(this);
        nam = new QNetworkAccessManager(this);

        // Signals
        connect(ircConnectBtn, &QPushButton::clicked, this, &MainWindow::ircConnectClicked);
        connect(ircSocket, &QTcpSocket::readyRead, this, &MainWindow::onIrcReadyRead);
        connect(ircSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error),
                this, &MainWindow::onIrcError);

        connect(httpStartBtn, &QPushButton::clicked, this, &MainWindow::startStopHttpServer);
        connect(httpServer, &QTcpServer::newConnection, this, &MainWindow::onNewHttpConnection);

        connect(nam, &QNetworkAccessManager::finished, this, &MainWindow::onBackendReply);

        appendIrcLog("Application started.");
    }

private slots:
    // ---------- IRC ----------
    void ircConnectClicked() {
        if (ircSocket->state() == QAbstractSocket::ConnectedState) {
            ircSocket->disconnectFromHost();
            appendIrcLog("Disconnecting IRC...");
            return;
        }
        QString server = ircServerEdit->text().trimmed();
        quint16 port = static_cast<quint16>(ircPortEdit->text().toUInt());
        if (server.isEmpty() || port == 0) {
            appendIrcLog("Invalid IRC server/port");
            return;
        }
        appendIrcLog(QString("Connecting to %1:%2 ...").arg(server).arg(port));
        ircSocket->connectToHost(server, port);
        // We'll wait for welcome messages in readyRead
        // Send NICK/USER after some milliseconds once connected
        connect(ircSocket, &QTcpSocket::connected, this, [this]() {
            QString nick = ircNickEdit->text().trimmed();
            if (nick.isEmpty()) nick = "qtproxydemo";
            ircSendRaw(QString("NICK %1").arg(nick));
            ircSendRaw(QString("USER %1 0 * :qt proxy demo").arg(nick));
            QTimer::singleShot(800, this, &MainWindow::ircJoinChannel);
            appendIrcLog("Sent NICK/USER");
        });
    }

    void ircJoinChannel() {
        QString chan = ircChannelEdit->text().trimmed();
        if (chan.isEmpty()) return;
        ircSendRaw(QString("JOIN %1").arg(chan));
        appendIrcLog(QString("Joining %1").arg(chan));
    }

    void onIrcReadyRead() {
        QByteArray ba = ircSocket->readAll();
        ircBuf += ba;
        while (true) {
            int idx = ircBuf.indexOf("\r\n");
            if (idx < 0) break;
            QByteArray line = ircBuf.left(idx);
            ircBuf = ircBuf.mid(idx + 2);
            QString s = QString::fromUtf8(line);
            appendIrcLog(QString("<< %1").arg(s));
            handleIrcLine(s);
        }
    }

    void handleIrcLine(const QString &line) {
        // Ping/Pong
        if (line.startsWith("PING ")) {
            QString token = line.mid(5);
            ircSendRaw(QString("PONG %1").arg(token));
            appendIrcLog("Responded to PING");
            return;
        }

        // PRIVMSG parsing: :nick!user@host PRIVMSG #chan :message
        QRegExp rx("^:([^!]+)!([^ ]+) PRIVMSG ([^ ]+) :(.*)$");
        if (rx.indexIn(line) != -1) {
            QString nick = rx.cap(1);
            QString target = rx.cap(3);
            QString msg = rx.cap(4);
            appendIrcLog(QString("[%1] %2").arg(nick).arg(msg));
            parseIrcMessage(nick, target, msg);
        }
    }

    void parseIrcMessage(const QString &nick, const QString &target, const QString &msg) {
        // We look for: !serve <host> <ip:port> or !serve <host> b64:<base64>
        if (!msg.startsWith("!serve ")) return;
        QString rest = msg.mid(7).trimmed();
        QStringList parts = rest.split(QRegExp("\\s+"), QString::SkipEmptyParts);
        if (parts.size() < 2) {
            appendIrcLog("!serve requires: host backend");
            return;
        }
        QString host = parts[0].trimmed();
        QString backend = parts[1].trimmed();

        // If backend is b64:xxxx decode
        if (backend.startsWith("b64:")) {
            QByteArray decoded = QByteArray::fromBase64(backend.mid(4).toUtf8());
            backend = QString::fromUtf8(decoded);
            appendIrcLog(QString("Decoded b64 backend to %1").arg(backend));
        }

        // Basic validation: expect ip:port or hostname:port
        if (!backend.contains(':')) {
            appendIrcLog("backend must be host:port");
            return;
        }

        // Save mapping
        mappings[host] = backend;
        refreshMappingTable();
        appendIrcLog(QString("Mapping set: %1 -> %2 (by %3)").arg(host).arg(backend).arg(nick));
    }

    void ircSendRaw(const QString &raw) {
        if (ircSocket->state() != QAbstractSocket::ConnectedState) return;
        QByteArray b = raw.toUtf8();
        b.append("\r\n");
        ircSocket->write(b);
        appendIrcLog(QString(">> %1").arg(raw));
    }

    void onIrcError(QAbstractSocket::SocketError socketError) {
        Q_UNUSED(socketError);
        appendIrcLog(QString("IRC socket error: %1").arg(ircSocket->errorString()));
    }

    // ---------- HTTP server ----------
    void startStopHttpServer() {
        if (httpServer->isListening()) {
            httpServer->close();
            appendHttpLog("HTTP server stopped.");
            return;
        }
        quint16 port = static_cast<quint16>(httpPortEdit->text().toUShort());
        if (port == 0) { appendHttpLog("Invalid HTTP port"); return; }
        if (!httpServer->listen(QHostAddress::Any, port)) {
            appendHttpLog(QString("Failed to listen on %1: %2").arg(port).arg(httpServer->errorString()));
        } else {
            appendHttpLog(QString("HTTP server listening on port %1").arg(port));
        }
    }

    void onNewHttpConnection() {
        while (httpServer->hasPendingConnections()) {
            QTcpSocket *cli = httpServer->nextPendingConnection();
            appendHttpLog(QString("New HTTP client %1:%2")
                          .arg(cli->peerAddress().toString()).arg(cli->peerPort()));
            connect(cli, &QTcpSocket::readyRead, this, [this, cli]() { handleHttpClientReadyRead(cli); });
            connect(cli, &QTcpSocket::disconnected, cli, &QTcpSocket::deleteLater);
        }
    }

    void handleHttpClientReadyRead(QTcpSocket *cli) {
        // Read until we have headers
        QByteArray &buf = clientBufs[cli];
        buf.append(cli->readAll());
        int idx = buf.indexOf("\r\n\r\n");
        if (idx < 0) return; // wait for full headers
        QByteArray headerBlock = buf.left(idx + 4);
        // For demo, we ignore any request body (GET only)
        QString headerText = QString::fromUtf8(headerBlock);
        QStringList lines = headerText.split("\r\n", QString::SkipEmptyParts);
        if (lines.isEmpty()) { cli->close(); return; }
        QString requestLine = lines[0];
        QStringList reqParts = requestLine.split(' ');
        if (reqParts.size() < 2) { cli->close(); return; }
        QString method = reqParts[0];
        QString path = reqParts[1]; // e.g. /example.com/foo

        appendHttpLog(QString("HTTP request: %1 %2").arg(method).arg(path));

        // Expect path like /host/rest...
        if (!path.startsWith("/")) {
            sendHttpSimple(cli, 400, "Bad Request", "Path must start with /");
            return;
        }
        QString pathNoLead = path.mid(1);
        int slashPos = pathNoLead.indexOf('/');
        QString hostPart;
        QString restPath;
        if (slashPos == -1) {
            hostPart = pathNoLead;
            restPath = "/";
        } else {
            hostPart = pathNoLead.left(slashPos);
            restPath = pathNoLead.mid(slashPos);
        }
        if (!mappings.contains(hostPart)) {
            sendHttpSimple(cli, 502, "Bad Gateway", QString("No mapping for host %1").arg(hostPart));
            return;
        }
        QString backend = mappings[hostPart]; // ip:port or host:port

        // Build backend URL: treat restPath as resource
        QString backendUrl = QString("http://%1%2").arg(backend).arg(restPath);
        appendHttpLog(QString("Proxying to backend URL: %1 (Host header: %2)").arg(backendUrl).arg(hostPart));

        // Prepare QNetworkRequest, set Host header to original hostPart
        QNetworkRequest req(QUrl(backendUrl));
        req.setRawHeader("Host", hostPart.toUtf8());
        // Copy other headers optionally — omitted for brevity

        // Perform asynchronous GET (we only do GET in demo)
        QNetworkReply *reply = nam->get(req);

        // Store mapping from reply -> client socket so we can respond when finished
        replyToClient[reply] = cli;
        // Clear client buffer to avoid reprocessing
        clientBufs.remove(cli);
        // ensure client is kept alive until we write back
        cli->setProperty("keepOpen", true);
    }

    void onBackendReply(QNetworkReply *reply) {
        QTcpSocket *client = replyToClient.value(reply, nullptr);
        replyToClient.remove(reply);
        if (!client) {
            appendHttpLog("No client socket for backend reply");
            reply->deleteLater();
            return;
        }

        if (reply->error() != QNetworkReply::NoError) {
            appendHttpLog(QString("Backend fetch error: %1").arg(reply->errorString()));
            sendHttpSimple(client, 502, "Bad Gateway", QString("Backend error: %1").arg(reply->errorString()));
            reply->deleteLater();
            return;
        }

        // Build HTTP response line + headers
        int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QVariant reasonVar = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
        QString reason = reasonVar.isValid() ? reasonVar.toString() : QString("OK");

        QByteArray response;
        response.append(QString("HTTP/1.1 %1 %2\r\n").arg(statusCode).arg(reason));
        // Copy Content-Type and Content-Length if present
        QVariant ct = reply->header(QNetworkRequest::ContentTypeHeader);
        if (ct.isValid()) response.append(QString("Content-Type: %1\r\n").arg(ct.toString()));
        QByteArray body = reply->readAll();
        response.append(QString("Content-Length: %1\r\n").arg(body.size()));
        // Minimal CORS + close
        response.append("Connection: close\r\n");
        response.append("\r\n");
        response.append(body);

        // Write to client and close
        client->write(response);
        client->flush();
        client->disconnectFromHost();
        appendHttpLog(QString("Proxied response to client %1:%2  (%3 bytes)")
                      .arg(client->peerAddress().toString()).arg(client->peerPort()).arg(body.size()));

        reply->deleteLater();
    }

private:
    // Helpers
    void refreshMappingTable() {
        mappingTable->setRowCount(0);
        for (auto it = mappings.begin(); it != mappings.end(); ++it) {
            int r = mappingTable->rowCount();
            mappingTable->insertRow(r);
            mappingTable->setItem(r, 0, new QTableWidgetItem(it.key()));
            mappingTable->setItem(r, 1, new QTableWidgetItem(it.value()));
        }
    }

    void appendIrcLog(const QString &s) {
        QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        ircLog->append(QString("[%1] %2").arg(ts).arg(s));
    }
    void appendHttpLog(const QString &s) {
        QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        httpLog->append(QString("[%1] %2").arg(ts).arg(s));
    }

    void sendHttpSimple(QTcpSocket *cli, int code, const QString &reason, const QString &body) {
        QByteArray resp;
        resp.append(QString("HTTP/1.1 %1 %2\r\n").arg(code).arg(reason));
        resp.append(QString("Content-Length: %1\r\n").arg(body.toUtf8().size()));
        resp.append("Connection: close\r\n");
        resp.append("Content-Type: text/plain\r\n");
        resp.append("\r\n");
        resp.append(body.toUtf8());
        cli->write(resp);
        cli->flush();
        cli->disconnectFromHost();
    }

    // UI
    QLineEdit *ircServerEdit;
    QLineEdit *ircPortEdit;
    QLineEdit *ircNickEdit;
    QLineEdit *ircChannelEdit;
    QTableWidget *mappingTable;
    QLineEdit *httpPortEdit;
    QTextEdit *ircLog;
    QTextEdit *httpLog;

    // Network
    QTcpSocket *ircSocket;
    QTcpServer *httpServer;
    QNetworkAccessManager *nam;

    // State
    QByteArray ircBuf;
    QMap<QString, QString> mappings; // host -> backend (ip:port)
    QMap<QTcpSocket*, QByteArray> clientBufs;
    QHash<QNetworkReply*, QTcpSocket*> replyToClient;
};

// main
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}

#include "irc_http_proxy_demo.moc"
