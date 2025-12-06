/*
	Example file paste application to demonstrate uwsd scripting capabilities.

	In order to test this application, ensure that the uwsd server is running
	with the shipped example configuration by invoking

		./uwsd --config example/paste.conf

	Once the uwsd server is started, navigate to <http://127.0.0.1:8080/> in
	your browser to view the application.
*/

'use strict';

import { basename, mkstemp } from 'fs';

const pasted_files = {};
let paste_counter = 0;

// Helper function to convert [sec, nsec] output of clock() to
// a time value in milliseconds
function clockms() {
	const t = clock(true);

	return (t[0] * 1000) + (t[1] / 1000000);
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
	// When we receove a PUT request, create context dictionary for the file
	// upload and attach it to the request context so that we can retrieve it
	// later in the onBody callback.
	if (method == 'PUT') {
		const mimetype = match(request.header('Content-Type'), /^([^/]+\/[^;[:space:]]+)\b/)?.[1];
		const filesize = request.header('Content-Length');

		// Require a length
		if (filesize == null) {
			return request.reply({
				'Status': '411 Length Required',
				'Content-Type': 'text/plain'
			}, 'The request must specify a Content-Length');
		}

		// Check that length is valid
		if (!match(filesize, /^[0-9]+$/)) {
			return request.reply({
				'Status': '400 Bad Request',
				'Content-Type': 'text/plain'
			}, 'Invalid Content-Length value in request');
		}

		// Ensure that length is below one megabyte
		if (+filesize > 1024 * 1024) {
			return request.reply({
				'Status': '413 Payload Too Large',
				'Content-Type': 'text/plain'
			}, 'Please do not upload files larger than 1MB');
		}

		// Check that upload mimetype is image/* or text/*
		if (!match(mimetype, /^(text|image)\//)) {
			return request.reply({
				'Status': '422 Unprocessable Entity',
				'Content-Type': 'text/plain'
			}, 'Please only upload image or text files');
		}

		// Create secure temporary file (it is unlinked already)
		const tempfile = mkstemp();

		// Create a unique file ID
		const file_uuid = uwsd.uuid();

		// Create file record
		const file_record = pasted_files[file_uuid] = {
			id: file_uuid,
			filesize: +filesize,
			mimetype,
			handle: tempfile,
			name: basename(request.uri()),
			sender_ua: request.header('User-Agent'),
			sender_ip: request.info()?.peer_address,
			duration: 0,
			uploaded: time(),
			...request.info()
		};

		// Store current time and file request in request context data
		request.data({
			request_start: clockms(),
			file_record
		});

		// Tell uwsd to write subsequent request body data to tempfile handle
		request.store(tempfile);
	}

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

	// We received an upload...
	if (request.method() == 'PUT') {
		ctx.file_record.duration = clockms() - ctx.request_start;

		return request.reply({
			'Status': '201 Created',
			'Content-Type': 'application/json',
			'Location': `/api/file/${ctx.file_record.id}`
		}, {
			name: ctx.file_record.name,
			url: `/file/${ctx.file_record.id}`
		});
	}

	// A delete request...
	else if (request.method() == 'DELETE') {
		let uri = request.uri();
		let m;

		// DELETE access to /api/file/#
		if ((m = match(uri, regexp('/file/([0-9a-f-]+)$'))) != null) {
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

	// A get request...
	else if (request.method() == 'GET') {
		let uri = request.uri();
		let m;

		// GET access to /api/file/#
		if ((m = match(uri, regexp('/file/([0-9a-f-]+)$'))) != null) {
			if (!exists(pasted_files, m[1])) {
				return request.reply({
					'Status': '404 Not Found',
					'Content-Type': 'text/plain'
				}, 'No such file ID');
			}

			pasted_files[m[1]].handle.seek(0, 0);

			return request.reply({
				'Status': '200 OK',
				'Content-Type': pasted_files[m[1]].mimetype
			}, pasted_files[m[1]].handle);
		}

		// GET access to /api/list/
		else if (match(uri, regexp('/list/?$'))) {
			return request.reply({
				'Status': '200 OK',
				'Content-Type': 'application/json'
			}, map(keys(pasted_files), (id, i) => ({
				mimetype: pasted_files[id].mimetype,
				filesize: pasted_files[id].filesize,
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

	// If it's not a PUT, GET or DELETE then reject it as we do not implement
	// other methods.
	else {
		return request.reply({
			'Status': '405 Method Not Allowed',
			'Content-Type': 'text/plain'
		}, 'Please only send GET, DELETE or PUT requests');
	}
};
