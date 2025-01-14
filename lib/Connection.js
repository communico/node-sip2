'use strict';

const net = require('net');
const tls = require('tls');
const parseResponse = require('../lib/parseResponse');

class Connection {

	constructor(host, port, proxyHost, proxyPort, sslOptions) {
		this.host = host;
		this.port = port;
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.socket = null;
		this.sslOptions = sslOptions || { enabled: false };
	}

	connect(callback) {
		this.socket = new net.Socket();
		this.socket.on('end', () => {
			//  console.log('Disconnected from SIP2 server');
		});

		this.socket.on('close', () => {
			//  console.log('SIP2 connection closed');
		});

		this.socket.on('error', (error) => {
			const message = error.code ? error.code : 'Unknown error';
			callback(`SIP2 connection error: ${message}`);
		});
		this.socket.on('timeout', () => {
			callback(`Timeout connecting to SIP2 server at ${this.host}:${this.port}`);
			this.socket.end();
		});
		if (this.proxyHost && this.proxyPort) {
			const socks5Handshake = Buffer.alloc(3);
			socks5Handshake[0] = 0x05; // SOCKS version number (must be 0x05 for this version)
			socks5Handshake[1] = 0x01; // Number of authentication methods supported.
			socks5Handshake[2] = 0x00; // 0x00: No authentication

			this.socket.connect(this.proxyPort, this.proxyHost, () => {
				// Socket connect done. Initiating Socks5 handshake
				this.socket.write(socks5Handshake);

				this.socket.once('data', (data) => {
					if (data.toString('hex') === "0500") {
						const addressLength = Buffer.byteLength(this.host);
						const requestBuffer = Buffer.alloc(7 + addressLength);
						let portOffset;

						requestBuffer[0] = 0x05; // SOCKS version number (must be 0x05 for this version)
						requestBuffer[1] = 0x01; // establish a TCP/IP stream connection
						requestBuffer[2] = 0x00; // reserved, must be 0x00
						requestBuffer[3] = 0x03; // address type, 1 byte. 0x03 = Domain name
						requestBuffer[4] = addressLength; // 1 byte of name length followed by the name for domain name
						requestBuffer.write(this.host, 5, addressLength);
						portOffset = 5 + addressLength;

						requestBuffer.writeUInt16BE(this.port, portOffset, true);
						this.socket.write(requestBuffer);
						this.socket.once('data', (data) => {
							if (data[1] !== 0) {
								this.socket.end();
								callback(`Socks5 connection request failed. Request denied, status: ${data[1]}`);
							} else {
								this.socket.setEncoding('utf8');
								callback();
							}
						});
					} else {
						this.socket.end();
						callback("Socks5 handshake failed. Closing the socket");
					}
				});
			});
		} else {
			this.socket.connect(this.port, this.host, this.handleConnection(callback));
			this.socket.setEncoding('utf8');
			this.socket.setTimeout(10000);
		}
		return this;
	}

	handleConnection(callback) {
		return (err) => {
			if (err) {
				return callback(err);
			}
			// Upgrade to TLS if needed
			if (this.sslOptions?.enabled) {
				return this.upgradeToTls(callback);
			}
			callback(); // Proceed without TLS if not enabled
		};
	}

	upgradeToTls(callback) {
		const options = {
			...this.sslOptions,
			host: this.host,
			socket: this.socket
		};
		this.socket = tls.connect(options, (err) => {
			callback(err);
		});
	}

	send(request, callback) {
		if (!this.socket) {
			callback(new Error('No open SIP2 socket connection'));
		}
		let data = '';
		this.socket.on('data', function getData(packet) {
			data += packet;
			if (/(\r\n|\r|\n)$/.exec(packet) !== null) {
				this.removeListener('data', getData);
				callback(null, parseResponse(data));
			}
		});
		this.socket.once('error', err => callback(err));
		this.socket.write(request);
	}

	close() {
		if (this.socket) {
			// Add message
			this.socket.end();
		}
	}
}

module.exports = Connection;