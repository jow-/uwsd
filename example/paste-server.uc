/*
	Example file paste application to demonstate uwsd scripting capabilities.

	In order to test this application, ensure that the uwsd server is running
	with the shipped example configuration by invoking

		./uwsd --config example/paste.conf

	Once the uwsd server is started, navigate to <http://127.0.0.1:8080/> in
	your browser to view the application.
*/

'use strict';

const pasted_files = {};
let paste_counter = 0;

// Helper function to convert [sec, nsec] output of clock() to
// a time value in milliseconds
function clockms() {
	const t = clock(true);

	return (t[0] * 1000) + (t[1] / 1000000);
}

// Helper function to extract the file payload from a multipart POST body
function filedata(ctype, body) {
	let boundary = match(ctype, /^multipart\/form-data;.*\bboundary=([^;]+)/)?.[1];

	if (!boundary)
		return null;

	if (substr(body, 0, 2) != '--' ||
	    substr(body, 2, length(boundary)) != boundary ||
	    substr(body, 2 + length(boundary), 2) != '\r\n' ||
	    substr(body, -(length(boundary) + 8), 4) != '\r\n--' ||
		substr(body, -(length(boundary) + 4), length(boundary)) != boundary ||
		substr(body, -4, 4) != '--\r\n')
	    return null;

	let chunks = split(
		substr(body, 4 + length(boundary), -(length(boundary) + 8)),
		`\r\n--${boundary}\r\n`
	);

	for (let chunk in chunks) {
		let header_payload = split(chunk, '\r\n\r\n', 2);
		let headers = {};
		let data;

		if (length(header_payload) == 2) {
			for (let header in split(header_payload[1] ? header_payload[0] : '', '\r\n')) {
				let nv = split(header, ':', 2);

				if (length(nv) == 2)
					headers[lc(trim(nv[0]))] = trim(nv[1]);
			}

			data = header_payload[1];
		}
		else {
			data = header_payload[0];
		}

		let cdisp = match(headers['content-disposition'], /^form-data;.*\bfilename=("(([^"\\]|\\.)+)"|'(([^'\\]|\\.)+)'|([^;]+\b))/);

		if (cdisp) {
			return {
				name: trim(length(cdisp[2]) ? cdisp[2] : (length(cdisp[4]) ? cdisp[4] : cdisp[6])),
				type: match(headers['content-type'], /^([^/]+\/[^;\s]+)\b/)?.[1],
				data
			};
		}
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
	// Create a context dictionary here and attach it to the request,
	// we'll use it as scratch space to accumulate some data.
	request.data({ request_start: clockms() });

	// Since we'll deal with the request in `onBody()` later, there's
	// not much left to do here. Simply log the received request to
	// stderr for diagnostic purposes.
	warn(`Received request: ${method} ${uri}\n`);
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
	let ctx = request.data();

	// Request specific details such as requested URI, HTTP method,
	// HTTP version and header are available through the `uri()`,
	// `method()`, `version()` and `header()` methods respectively.

	// We're receiving an upload...
	if (request.method() == 'POST') {
		// Limit upload size to 1MB total
		if (length(ctx.body) + length(data) > 1048576) {
			return request.reply({
				'Status': '413 Payload Too Large',
				'Content-Type': 'text/plain'
			}, 'Please do not upload files larger than 1MB');
		}

		// Not the final chunk, store in context and return
		if (length(data)) {
			ctx.body = ctx.body ? ctx.body + data : data;

			return;
		}
	}

	// If it's not a POST, it should be a GET or DELETE.
	// Reject other methods as we do not implement them.
	else if (!(request.method() in ['GET', 'DELETE'])) {
		return request.reply({
			'Status': '405 Method Not Allowed',
			'Content-Type': 'text/plain'
		}, 'Please only send GET, DELETE or POST requests');
	}

	// At this point we completely received our request, see if it
	// was a file upload (POST) or download (GET) and deal with it
	// accordingly...
	if (ctx.body) {
		let file = filedata(request.header('Content-Type'), ctx.body);

		if (!file) {
			return request.reply({
				'Status': '422 Unprocessable Entity',
				'Content-Type': 'text/plain'
			}, 'Unable to find file data in POST request body');
		}

		pasted_files[paste_counter] = {
			mimetype: file.type,
			data: file.data,
			name: file.name,
			sender_ua: request.header('User-Agent'),
			sender_ip: request.info()?.peer_address,
			duration: clockms() - ctx.request_start,
			uploaded: time(),
			...request.info()
		};

		return request.reply({
			'Status': '200 OK',
			'Content-Type': 'application/json'
		}, {
			mimetype: file.type,
			name: file.name,
			url: `/file/${paste_counter++}`
		});
	}
	else if (request.method() == 'DELETE') {
		let uri = request.uri();
		let m;

		// DELETE access to /api/file/#
		if ((m = match(uri, regexp('/file/([0-9]+)$'))) != null) {
			if (!exists(pasted_files, m[1])) {
				return request.reply({
					'Status': '404 Not Found',
					'Content-Type': 'text/plain'
				}, 'No such file ID');
			}

			delete pasted_files[m[1]];

			return request.reply({
				'Status': '200 OK',
				'Content-Type': 'text/plain'
			}, `File ID ${m[1]} has been deleted`);
		}
		else {
			return request.reply({
				'Status': '405 Method Not Allowed',
				'Content-Type': 'text/plain'
			}, 'The requested resource cannot be deleted');
		}
	}
	else {
		let uri = request.uri();
		let m;

		// GET access to /api/file/#
		if ((m = match(uri, regexp('/file/([0-9]+)$'))) != null) {
			if (!exists(pasted_files, m[1])) {
				return request.reply({
					'Status': '404 Not Found',
					'Content-Type': 'text/plain'
				}, 'No such file ID');
			}

			return request.reply({
				'Status': '200 OK',
				'Content-Length': length(pasted_files[m[1]].data),
				'Content-Type': pasted_files[m[1]].mimetype
			}, pasted_files[m[1]].data);
		}

		// GET access to /api/list/
		else if (match(uri, regexp('/list/?$'))) {
			return request.reply({
				'Status': '200 OK',
				'Content-Type': 'application/json'
			}, map(keys(pasted_files), (id, i) => ({
				mimetype: pasted_files[id].mimetype,
				name: pasted_files[id].name,
				sender_ua: pasted_files[id].sender_ua,
				sender_ip: pasted_files[id].sender_ip,
				duration: pasted_files[id].duration,
				uploaded: pasted_files[id].uploaded,
				url: `/file/${id}`
			})));
		}

		// other, unrecognized URL
		else {
			return request.reply({
				'Status': '404 Not Found',
				'Content-Type': 'text/plain'
			}, 'No such endpoint');
		}
	}

	return 1;
};
