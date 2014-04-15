from calltrace import traced

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit
#~ import socketserver
from http.client import (
    REQUEST_URI_TOO_LONG, NOT_FOUND, REQUEST_HEADER_FIELDS_TOO_LARGE,
)
from http.client import NOT_IMPLEMENTED, INTERNAL_SERVER_ERROR
from http.client import OK
import email.parser, email.message
from functions import setitem
from io import BytesIO
import subprocess
import sys
import random
from functions import attributes

RTSP_PORT = 554

_SESSION_DIGITS = 25

#~ class Server(socketserver.ThreadingMixIn, HTTPServer):
class Server(HTTPServer):
    def __init__(self, file, address=("", RTSP_PORT), *, ffmpeg2=True):
        """ffmpeg2: Assume FF MPEG 2.1 rather than libav 0.8.6"""
        self._file = file
        self._ffmpeg2 = ffmpeg2
        self._sessions = dict()
        (self._sdp, self._streams) = self._get_sdp(self._file)
        HTTPServer.__init__(self, address, Handler)
    
    def _get_sdp(self, file):
        options = ("-t", "0")  # Stop before processing any video
        streams = ((type, None) for type in self._streamtypes)
        ffmpeg = self._ffmpeg(file, options, streams,
            stdout=subprocess.PIPE, bufsize=-1,
        )
        with ffmpeg:
            sdp = BytesIO()
            line = ffmpeg.stdout.readline()
            
            # FF MPEG unhelpfully adds this prefix to its output
            if line.strip() == b"SDP:":
                line = ffmpeg.stdout.readline()
            
            streams = 0
            while line:
                if not line.strip():
                    break
                if not line.startswith(b"a=control:"):
                    sdp.write(line)
                
                if line.startswith(b"m="):
                    line = "a=control:{}\r\n".format(streams)
                    streams += 1
                    sdp.write(line.encode("ascii"))
                
                line = ffmpeg.stdout.readline()
            else:
                with ffmpeg:
                    pass  # Close and wait for process
                msg = "FF MPEG failed generating SDP data; exit status: {}"
                raise EnvironmentError(msg.format(ffmpeg.returncode))
        return (sdp.getvalue(), streams)
    
    def handle_error(*pos, **kw):
        exc = sys.exc_info()[0]
        if issubclass(exc, ConnectionError):
            return
        if not issubclass(exc, Exception):
            raise  # Force server loop to exit
        HTTPServer.handle_error(*pos, **kw)
    
    def server_close(self, *pos, **kw):
        while self._sessions:
            (_, session) = self._sessions.popitem()
            session.end()
        return HTTPServer.server_close(self, *pos, **kw)
    
    _streamtypes = ("video", "audio")
    
    def _ffmpeg(self, file, options, streams, **popenargs):
        """Spawn an FF MPEG child process
        
        * options: CLI arguments to include
        * streams: Output an RTP stream for each of these
        """
        cmd = ["ffmpeg", "-loglevel", "warning"]
        cmd.extend(options)
        cmd.extend(("-i", file))
        
        first = True
        for (type, address) in streams:
            t = type[0]
            if self._ffmpeg2:
                cmd.extend(("-map", "0:" + t))
            cmd.extend(("-{}codec".format(t), "copy"))
            cmd.extend("-{}n".format(other[0]) for
                other in self._streamtypes if other != type)
            
            cmd.extend(("-f", "rtp"))
            if address:
                (host, port) = address
                if ":" in host:
                    host = "[{}]".format(host)
                cmd.append("rtp://{}:{}".format(host, port))
            elif self._ffmpeg2:
                cmd.append("rtp://localhost:1")
            else:
                cmd.append("rtp://localhost")
            
            if not self._ffmpeg2 and not first:
                cmd += ("-new" + type,)
            first = False
        
        return subprocess.Popen(cmd, **popenargs)

class Handler(BaseHTTPRequestHandler):
    protocol_version = "RTSP/1.0"
    responses = dict(BaseHTTPRequestHandler.responses)  # Extended below
    
    def handle_one_request(self):
        try:
            self.close_connection = True
            self.request_version = None
            self.headers = self.MessageClass()
            self.response_started = False
            try:
                self.requestline = self.rfile.readline(1000 + 1)
                if not self.requestline:
                    return
                if len(self.requestline) > 1000:
                    msg = "Request line too long"
                    raise ErrorResponse(REQUEST_URI_TOO_LONG, msg)
                
                self.requestline = self.requestline.decode("latin-1")
                self.requestline = self.requestline.rstrip("\r\n")
                split = self.requestline.split(maxsplit=3)
                self.command, self.path, self.request_version = split[:3]
                
                parser = email.parser.BytesFeedParser(
                    _factory=self.MessageClass)
                for _ in range(200):
                    line = self.rfile.readline(1000 + 1)
                    if len(line) > 1000:
                        code = REQUEST_HEADER_FIELDS_TOO_LARGE
                        msg = "Request header line too long"
                        raise ErrorResponse(code, msg)
                    parser.feed(line)
                    if not line.rstrip(b"\r\n"):
                        break
                else:
                    msg = "Request header too long"
                    raise ErrorResponse(REQUEST_HEADER_FIELDS_TOO_LARGE, msg)
                self.headers = parser.close()
                
                self.close_connection = False
                handler = self.handlers.get(self.command,
                    type(self).handle_request)
                handler(self)
            
            except ErrorResponse as resp:
                self.send_error(resp.code, resp.message)
        except Exception as err:
            self.server.handle_error(self.request, self.client_address)
            if self.response_started:
                self.close_connection = True
            else:
                self.send_error(INTERNAL_SERVER_ERROR, err)
    
    def send_error(self, code, message=None):
        self.send_response(code, message)
        self.end_headers()
    
    def send_response(self, *pos, **kw):
        self.response_started = True
        BaseHTTPRequestHandler.send_response(self, *pos, **kw)
        for cseq in self.headers.get_all("CSeq", ()):
            self.send_header("CSeq", cseq)
    
    handlers = dict()
    
    @setitem(handlers, "OPTIONS")
    def handle_options(self):
        if self.path != "*" and urlsplit(self.path).path:
            try:
                (key, session) = self.get_session()
                stream = self.parse_stream()
            except ErrorResponse as resp:
                self.send_response(resp.code, resp.message)
            else:
                self.send_response(OK)
                self.send_allow(key, session, stream)
        else:
            self.send_response(OK)
        self.send_public()
        self.end_headers()
    
    def handle_request(self):
        msg = 'Request method "{}" not implemented'.format(self.command)
        self.send_response(NOT_IMPLEMENTED, msg)
        self.send_public()
        self.end_headers()
    
    @setitem(handlers, "DESCRIBE")
    def handle_describe(self):
        if self.parse_stream() is not None:
            raise ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        
        self.send_response(OK)
        self.send_header("Content-Type", "application/sdp")
        self.send_header("Content-Length", len(self.server._sdp))
        self.end_headers()
        self.wfile.write(self.server._sdp)
    
    @setitem(handlers, "SETUP")
    def handle_setup(self):
        (key, session) = self.get_session()
        stream = self.parse_stream()
        if stream is None:
            if self.server._streams > 1:
                msg = "{} streams available".format(self.server._streams)
                raise ErrorResponse(AGGREGATE_OPERATION_NOT_ALLOWED, msg)
            stream = 0
        if session.ffmpeg:
            msg = "SETUP not supported while streaming"
            self.send_invalidstate(key, session, stream, msg)
            return
        
        error = None
        for transports in self.headers.get_all("Transport", ()):
            if '"' in transports:
                multierror = error
                error = "Parsing quotes not implemented"
                continue
            
            for transport in transports.split(","):
                try:
                    transport = transport.strip()
                    
                    params = transport.split(";")
                    udp = params[0].strip() in {"RTP/AVP", "RTP/AVP/UDP"}
                    
                    unicast = False
                    port = None
                    interleaved = None
                    ilstart = None
                    for param in params[1:]:
                        (name, _, value) = param.partition("=")
                        name = name.strip()
                        value = value.strip()
                        
                        unicast = unicast or name == "unicast" and not value
                        if (name == "mode" and value and
                        frozenset((value,)) != {"PLAY"}):  # TODO: parse comma-separated list
                            raise ValueError("Only mode=PLAY supported")
                        
                        if name == "interleaved":
                            interleaved = True
                            if ilstart is not None:
                                msg = 'Multiple "interleaved" parameters'
                                raise ValueError(msg)
                            (ilstart, _, end) = value.partition("-")
                            ilstart = int(ilstart)
                            if end and int(end) != ilstart + 1:
                                msg = "Only pair of channels supported"
                                raise ValueError(msg)
                        
                        if name == "client_port" and value:
                            if port is not None:
                                msg = 'Multiple "client_port" parameters'
                                raise ValueError(msg)
                            (port, _, end) = value.partition("-")
                            port = int(port)
                            if end and int(end) != port + 1:
                                msg = "Only pair of ports supported"
                                raise ValueError(msg)
                    
                    if interleaved:
                        if ilstart is None:
                            raise ValueError("Interleaved channel not given")
                        msg = "Interleaved transport not yet implemented"
                        raise ValueError(msg)
                    if udp and unicast:
                        if port is None:
                            raise ValueError("Unicast UDP port not given")
                        break
                    msg = ("Only unicast UDP and interleaved transports "
                        "supported")
                    raise ValueError(msg)
                
                except ValueError as exc:
                    multierror = error
                    error = format(exc)
            else:  # No suitable transport found
                continue
            break  # Stopped on suitable transport
        else:  # No suitable transport found
            if not error or multierror:
                error = ("No supported unicast UDP or interleaved transport "
                    "given")
            raise ErrorResponse(UNSUPPORTED_TRANSPORT, error)
        
        if key is None:
            key = random.getrandbits(_SESSION_DIGITS * 4)
            self.server._sessions[key] = session
        session.addresses[stream] = (self.client_address[0], port)
        
        self.send_response(OK)
        self.send_session(key)
        self.send_header("Transport", transport)
        self.end_headers()
    
    @setitem(handlers, "TEARDOWN")
    def handle_teardown(self):
        (key, session) = self.get_session()
        if not key:
            raise ErrorResponse(SESSION_NOT_FOUND, "No session given")
        stream = self.parse_stream()
        if stream is None:
            self.server._sessions.pop(key).end()
        else:
            msg = None
            if not session.addresses[stream]:
                msg = "Stream {} not set up".format(stream)
            elif session.ffmpeg and session.other_addresses(stream):
                msg = "Partial TEARDOWN not supported while streaming"
            if msg:
                self.send_invalidstate(key, session, stream, msg)
                return
            
            session.addresses[stream] = None
            if not any(session.addresses):
                self.server._sessions.pop(key).end()
        
        self.send_response(OK)
        if key in self.server._sessions:
            self.send_session(key)
        self.end_headers()
    
    @setitem(handlers, "PLAY")
    def handle_play(self):
        (key, session) = self.get_session()
        if not key:
            raise ErrorResponse(SESSION_NOT_FOUND, "No session given")
        addresses = session.addresses
        stream = self.parse_stream()
        if stream is not None:
            if not addresses[stream]:
                msg = "Stream {} not set up".format(stream)
                self.send_invalidstate(key, session, stream, msg)
                return
            if session.other_addresses(stream):
                raise ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        if session.ffmpeg:
            msg = "PLAY not supported while already streaming"
            self.send_invalidstate(key, session, stream, msg)
            return
        
        options = ("-re",)
        streams = ((type, address) for (type, address) in
            zip(self.server._streamtypes, addresses) if address)
        session.ffmpeg = self.server._ffmpeg(
            self.server._file, options, streams, stdout=subprocess.DEVNULL)
        self.send_response(OK)
        self.end_headers()
    
    #~ @setitem(handlers, "PAUSE")
    #~ def handle_pause(self):
        #~ return self.handle_request()
    
    def parse_stream(self):
        path = urlsplit(self.path).path.lstrip("/")
        if not path:
            return None
        try:
            stream = int(path)
        except ValueError as err:
            raise ErrorResponse(NOT_FOUND, err)
        if stream not in range(self.server._streams):
            msg = "Stream number out of range 0-{}"
            msg = msg.format(self.server._streams - 1)
            raise ErrorResponse(NOT_FOUND, msg)
        return stream
    
    def get_session(self):
        key = self.headers.get("Session")
        if key is None:
            return (None, Session(self.server._streams))
        try:
            key = int(key, 16)
        except ValueError as err:
            raise ErrorResponse(SESSION_NOT_FOUND, err)
        session = self.server._sessions.get(key)
        if session is None:
            raise ErrorResponse(SESSION_NOT_FOUND)
        return (key, session)
    
    def send_public(self):
        self.send_header("Public", ", ".join(self.handlers.keys()))
    
    def send_allow(self, session_key, session, stream):
        allow = ["OPTIONS"]
        if stream is None:
            allow.append("DESCRIBE")
        singlestream = stream is not None or self.server._streams <= 1
        if singlestream and not session.ffmpeg:
            allow.append("SETUP")
        if session_key is not None:
            allstreams = (stream is None or session.addresses[stream] and
                not session.other_addresses(stream))
            if (allstreams or
            session.addresses[stream] and not session.ffmpeg):
                allow.append("TEARDOWN")
            if not session.ffmpeg and allstreams:
                allow.append("PLAY")
        self.send_header("Allow", ", ".join(allow))
    
    def send_session(self, key):
        key = format(key, "0{}X".format(_SESSION_DIGITS))
        self.send_header("Session", key)
    
    def send_invalidstate(self, key, session, stream, msg=None):
        self.send_response(METHOD_NOT_VALID_IN_THIS_STATE, msg)
        self.send_allow(key, session, stream)
        self.end_headers()

for (code, message) in (
    (454, "Session Not Found"),
    (455, "Method Not Valid In This State"),
    (459, "Aggregate Operation Not Allowed"),
    (460, "Only Aggregate Operation Allowed"),
    (461, "Unsupported Transport"),
):
    symbol = "_".join(message.split()).upper()
    globals()[symbol] = code
    Handler.responses[code] = (message,)

class Session:
    def __init__(self, streams):
        self.addresses = [None] * streams
        self.ffmpeg = None
    
    def end(self):
        if self.ffmpeg:
            self.ffmpeg.terminate()
            self.ffmpeg.wait()
    
    def other_addresses(self, stream):
        return (any(self.addresses[:stream]) or
            any(self.addresses[stream + 1:]))

class ErrorResponse(Exception):
    def __init__(self, code, message=None):
        self.code = code
        self.message = message
        Exception.__init__(self, self.code)

@attributes(param_types=dict(port=int))
def main(file, port=RTSP_PORT, *, noffmpeg2=False):
    server = Server(file, ("", port), ffmpeg2=not noffmpeg2)
    try:
        server.serve_forever()
    finally:
        server.server_close()

if __name__ == "__main__":
    try:
        from funcparams import command
        command()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
