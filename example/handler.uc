'use strict';

import { timer } from 'uloop';

function timer_cb(connection) {
	connection.send('Unsolicited send!!\n');
	timer(1000, () => timer_cb(connection));
}

export function onConnect(connection, protocols)
{
	warn(`Connect! ${connection} ${protocols}\n`);

	if (!('shell' in protocols))
		return connection.close(1003, 'Unsupported protocol requested');

	connection.data({
		counter: 0,
		n_messages: 0,
		n_fragments: 0
	});

	timer(1000, () => timer_cb(connection));

	return connection.accept('shell');
};

export function onData(connection, data, final)
{
	let ctx = connection.data();

	warn(`Data! ${connection} [${ctx}]\n`);

	if (length(ctx.msg) + length(data) > 4096)
		return connection.close(1009, 'Message too big');

	if (final) {
		ctx.n_messages++;
		ctx.n_fragments = 0;
	}
	else {
		ctx.n_fragments++;
	}

	let msg = ctx.n_fragments ? ctx.msg + data : data;

	switch (data) {
	case 'stats':
		connection.send(`Counter: ${ctx.counter} / Messages: ${ctx.n_messages} / Fragments: ${ctx.n_fragments}\n`);
		break;

	case 'inc':
		ctx.counter++;
		connection.send(`Counter is now: ${ctx.counter}\n`);
		break;

	case 'time':
		let tm = localtime();
		connection.send(`Current local time is: ${sprintf('%04d-%02d-%02dT%02d:%02d:%02d', tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec)}\n`);
		break;

	default:
		connection.send(`Unrecognized request\n`);
		break;
	}
};

export function onClose(connection, code, reason)
{
	warn(`Connection has been closed: ${code ?? '-'} (${reason ?? 'Unspecified reason'})\n`);
};


export function onRequest(request)
{
	request.data('');
};

export function onBody(request, data)
{
	request.data(request.data() + data);

	if (data == '') {
		request.reply({
			'Status': '200 OK',
			'Content-Type': 'text/plain',
		}, request.data() || 'no request data');
	}
};
