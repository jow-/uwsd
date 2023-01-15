/*
	Example chat application to demonstate uwsd scripting capabilities.

	In order to test this application, ensure that the uwsd server is running
	with the shipped example configuration by invoking

		./uwsd --config example/chat.conf

	Once the uwsd server is started, navigate to <http://127.0.0.1:8080/> in
	your browser to view the application.
*/

'use strict';

import { timer } from 'uloop';

const connected_clients = {};
const max_message_size = +getenv('MAX_MESSAGE_SIZE') || 4096;
const status_interval = +getenv('STATUS_INTERVAL') || 5000;

function unicast(conn, msg) {
	conn.send(`${{...msg, time: time()}}`);
}

function broadcast(msg) {
	for (let key, client in connected_clients)
		unicast(client, msg);
}

function broadcast_status() {
	const tm = localtime();
	const ts = sprintf('%04d-%02d-%02dT%02d:%02d:%02d', tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec);

	broadcast({
		type: 'server-status',
		msg: `The time is now ${ts}, there are ${length(connected_clients)} clients connected`
	});

	timer(status_interval, broadcast_status);
}

// This callback is invoked when a WebSocket handshake is received,
// it receives a connection context as first and an array of client
// provided sub protocols as second argument.
//
// The callback must invoke `connection.accept([subprotocol])` to
// accept the incoming handshake.
//
// When this callback returns without invoking `connection.accept()`
// then the WebSocket handshake is rejected.
export function onConnect(connection, protocols)
{
	// Reject handshakes not supporting our chat sub protocol
	if (!('uwsd.example.chat' in protocols))
		return connection.close(1003, 'Unsupported protocol requested');

	// Prepare context data, form an initial nickname
	let ctx = {
		bytes: 0,
		messages: 0,
		seen: time(),
		joined: time(),
		nickname: `Anonymous_${match(connection, /0x[[:xdigit:]]*([[:xdigit:]]{4})/)?.[1]}`,
		conninfo: connection.info()
	};

	// Send nickname notification, followed by greeting message
	timer(1, function() {
		unicast(connection, { type: 'nickname-change', nickname: ctx.nickname });
		unicast(connection, { type: 'server-message', msg: `Welcome, ${ctx.nickname}!` });
	});

	// Notify all other connected users about this new client
	broadcast({
		type: 'server-message',
		msg: `${ctx.nickname} connected!`
	});

	// Store client specific context data
	connection.data(ctx);

	// Register connection
	connected_clients[connection] = connection;

	// Accept the ws handshake using the "uwsd.example.chat" sub protocol
	return connection.accept('uwsd.example.chat');
};

// This callback is invoked when a chunk of WebSocket application data
// is received. It receives the connection context, a string containing
// the chunk of data and a boolean flag indicating the final chunk as
// first, second and third argument respectively.
export function onData(connection, data, final)
{
	// Obtain or client specific context data
	let ctx = connection.data();

	// Reject too long messages
	if (length(ctx.buffer) + length(data) > max_message_size)
		return connection.close(1009, 'Message too big');

	// Buffer data in context
	ctx.buffer = ctx.buffer ? ctx.buffer + data : data;

	// If this is not the final chunk, return
	if (!final)
		return;

	// JSON decode message
	let msg = json(ctx.buffer);

	// Update some stats
	ctx.seen = time();
	ctx.messages++;
	ctx.bytes += length(ctx.buffer);

	// Delete temporary buffer
	delete ctx.buffer;

	// Handle incoming command
	switch (msg?.command) {
	case 'set-nickname':
		// A simple nickname sanity check
		if (!match(msg.value, /^[^[:cntrl:][:space:]]{3,}$/)) {
			return unicast(connection, {
				type: 'server-error',
				msg: `Invalid nickname, must be at least 3 characters long and not contain spaces or control characters`
			});
		}

		// Check for nickname uniqueness
		for (let key, conn in connected_clients) {
			if (conn != connection) {
				if (conn.data()?.nickname == msg.value) {
					return unicast(connection, {
						type: 'server-error',
						msg: 'The chosen nickname is already taken'
					});
				}
			}
		}

		// Send nickname change confirmation
		unicast(connection, {
			type: 'nickname-change',
			nickname: msg.value
		});

		// Notfiy about nickname change
		broadcast({
			type: 'server-message',
			msg: `${ctx.nickname} is now known as ${msg.value}`
		});

		ctx.nickname = msg.value;
		break;

	case 'send-message':
		// Send received message to all clients
		broadcast({
			type: 'client-message',
			from: ctx.nickname,
			msg: msg.value
		});
		break;

	case 'list-clients':
		// Send back to requesting client
		unicast(connection, {
			type: 'client-list',
			clients: map(values(connected_clients), cctx => cctx.data())
		});
		break;

	case 'ping':
		// Send a pong message
		unicast(connection, { type: 'pong' });
		break;

	default:
		unicast(connection, {
			type: 'server-message',
			msg: `Unrecognized command received`
		});
		break;
	}
};

// The `onClose()` callback is invoked when the websocket connection
// is closed normally or abnormally by either the server or client.
// When called, it will receive the connection context, a numerical
// reason code as well as an implementation specific reason message
// as first, second and third argument respecitvely.
export function onClose(connection, code, reason)
{
	// Obtain or client specific context data
	let ctx = connection.data();

	// Delete connection from connected client registry
	delete connected_clients[connection];

	// Notify remaining clients about the disconnect
	broadcast({
		type: 'server-message',
		msg: `Client ${ctx.nickname} has left the chat`
	});
};

// Send current status to all connected clients every 5 seconds
timer(status_interval, broadcast_status);
