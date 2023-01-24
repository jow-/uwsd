/*
	Example wrapper script to emulate a CGI gateway under uwsd.

	In order to test this application, ensure that the uwsd server is running
	with the shipped example configuration by invoking

		./uwsd --config example/cgi.conf

	Once the uwsd server is started, navigate to <http://127.0.0.1:8080/> in
	your browser to view the application.
*/

'use strict';

import * as fs from 'fs';

function server_name(host_header, local_address) {
	let m;

	if (host_header != null) {
		if ((m = match(host_header, /^\[([[:xdigit:]:]+)\]:\d{1,5}$/)) != null)
			return `[${iptoarr(arrtoip(m[1]))}]`;

		if ((m = match(host_header, /^([^:]+):\d{1,5}$/)) != null)
			return m[1];

		return host_header;
	}

	let addr = iptoarr(local_address);

	switch (length(addr)) {
	case 16: return `[${arrtoip(addr)}]`;
	default: return arrtoip(addr);
	}
}

function lookup_script(request) {
	let docroot = fs.realpath(getenv('DOCUMENT_ROOT') ?? '.');
	let uri = split(request.uri(), '?', 2)[0];
	let segments = filter(split(uri, '/'), length);
	let pathinfo = [];

	for (let i = 0; i < length(segments); i++)
		if (segments[i] == '..')
			return null;

	while (length(segments)) {
		let path = fs.realpath(`${docroot}/${join('/', segments)}`);
		let st = path ? fs.stat(path) : null;

		if (st?.type == 'file')
			return {
				path,
				root: docroot,
				name: `/${join('/', segments)}`,
				info: length(pathinfo) ? `/${join('/', pathinfo)}` : null,
				translated: length(pathinfo) ? `${docroot}/${join('/', pathinfo)}` : null,
				stat: st
			};

		unshift(pathinfo, pop(segments));
	}

	return null;
}

// This callback is invoked when the header portion of an HTTP request
// is received. Depending on the type of request, the client might
// follow up with subsequent request body data, which is handled by
// the `onBody()` callback below.
//
// The `onRequest()` callback receives the request context, the
// HTTP request method name and the requested URI as first, second
// and third function argument respectively.
//
// If the application is not interested in the subsequent request
// body, or if it wishes to answer the request right away (e.g. to
// reject a POST request or similar), it might already send a reply
// using `connection.reply([headers[, body]])` here.
export function onRequest(request, method, uri)
{
	// Find requested script
	let script = lookup_script(request);

	if (!script) {
		return request.reply({
			'Status': '404 Not Found',
			'Content-Type': 'text/plain'
		}, 'The requested CGI script was not found on this server');
	}

	if (!(script.stat.perm.other_read && script.stat.perm.other_exec)) {
		return request.reply({
			'Status': '403 Permission Denied',
			'Content-Type': 'text/plain'
		}, 'Insufficient filesystem permissions to invoked the requested script');
	}

	// Obtain connection info
	let conn_info = request.info();

	// Prepare CGI environment
	let cgi_env = {
		SERVER_SOFTWARE: 'uwsd',
		SERVER_NAME: server_name(request.header('Host'), conn_info.local_address),
		SERVER_ADDR: conn_info.local_address,
		SERVER_PORT: conn_info.local_port,
		GATEWAY_INTERFACE: 'CGI/1.1',
		CONTENT_TYPE: request.header('Content-Type'),
		REMOTE_ADDR: conn_info.peer_address,
		REMOTE_PORT: conn_info.peer_port,
		REQUEST_METHOD: method,
		REQUEST_URI: uri,
		SERVER_PROTOCOL: sprintf('HTTP/%3.1f', request.version()),
		SCRIPT_NAME: script.name,
		SCRIPT_FILENAME: script.path,
		PATH_INFO: script.info,
		PATH_TRANSLATED: script.translated,
		QUERY_STRING: '',
		DOCUMENT_ROOT: script.root,
		PATH: getenv('PATH'),
	};

	let m;

	switch (lc(m = match(request.header('Authorization', /^(\S+)\s+/))?.[1] ?? '')) {
	case 'basic':  cgi_env.AUTH_TYPE = 'Basic';  break;
	case 'digest': cgi_env.AUTH_TYPE = 'Digest'; break;
	case '':                                     break;
	default:       cgi_env.AUTH_TYPE = m;        break;
	}

	if ((m = request.header('Content-Length')) != null)
		cgi_env.CONTENT_LENGTH = m;

	if ((m = match(uri, /\?(.*)$/)?.[1]) != null)
		cgi_env.QUERY_STRING = m;

	if (conn_info.ssl)
		cgi_env.HTTPS = 'on';

	for (let hdrname, hdrvalue in request.header())
		cgi_env[`HTTP_${uc(replace(hdrname, /\W+/g, '_'))}`] = hdrvalue;

	// Spawn script process
	let proc = spawn(script.path, [ script.path ], cgi_env);

	// Store process handle in the request context
	request.data(proc);
};

// The `onBody()` callback is invoked when a chunk of the HTTP request
// body data is received. It might get invoked multiple times until the
// entire request has been handled by the uwsd server. Once the entire
// request body is completed, this callback is invoked once more with
// an empty string to signal EOF.
//
// If defined, this callback is guaranteed to be invoked at least once
// with an empty string argument for each received HTTP request, even
// for requests without any body data. This simplifies implementing
// generic handler logic dealing with both body-less (e.g. GET/HEAD)
// and body-carrying requests (e.g. PUT/POST).
//
// On invocation, the callback will receive the request context and
// a body data chunk (or an empty string to signal EOF) as first and
// second argument respectively.
//
// Upon receiving EOF and after processing the received request (or in
// case of an error), the callback should emit an HTTP reply by invoking
// `connection.reply([headers[, body]])` here.
export function onBody(request, data)
{
	// Get back process handle from request context
	let proc = request.data();

	if (!proc)
		return;

	// On input data, send it to the process stdin pipe and return
	if (length(data)) {
		proc.stdin().write(data);

		return;
	}

	// On EOF, close process stdin and begin processing output
	proc.stdin().close();

	// Forward script output
	for (let chunk = proc.stdout().read(4096); length(chunk); chunk = proc.stdout().read(4096))
		request.send(chunk);

	// Terminate program
	proc.close();
};
