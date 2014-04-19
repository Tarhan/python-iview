from calltrace import traced

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
#~ import socketserver
from http.client import (
    REQUEST_URI_TOO_LONG, NOT_FOUND, REQUEST_HEADER_FIELDS_TOO_LARGE,
    METHOD_NOT_ALLOWED,
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
from collections.abc import Mapping
import urllib.parse
from misc import formataddr, urlbuild
from misc import joinpath

RTSP_PORT = 554

_SESSION_DIGITS = 25

#~ class Server(socketserver.ThreadingMixIn, HTTPServer):
class Server(HTTPServer):
    def __init__(self, address=("", RTSP_PORT), *, ffmpeg2=True):
        """ffmpeg2: Assume FF MPEG 2.1 rather than libav 0.8.6"""
        self._ffmpeg2 = ffmpeg2
        self._sessions = dict()
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
                end = not line.strip()
                if (end or line.startswith(b"m=")) and streams:
                    control = "a=control:{}\r\n".format(streams - 1)
                    sdp.write(control.encode("ascii"))
                if end:
                    break
                
                if line.startswith(b"m="):
                    fields = line.split(maxsplit=3)
                    PORT = 1
                    PROTO = 2
                    fields[PORT] = b"0"  # VLC hangs or times out otherwise
                    fields[PROTO] = b"TCP/RTP/AVP"
                    line = b" ".join(fields)
                    streams += 1
                if not line.startswith(b"a=control:"):
                    sdp.write(line)
                
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
        
        for (i, (type, address)) in enumerate(streams):
            t = type[0]
            if self._ffmpeg2:
                cmd.extend(("-map", "0:" + t))
            cmd.extend(("-{}codec".format(t), "copy"))
            cmd.extend("-{}n".format(other[0]) for
                other in self._streamtypes if other != type)
            
            cmd.extend(("-f", "rtp"))
            if not address:
                # Avoid null or zero port because FF MPEG emits an error,
                # although only after outputting the SDP data,
                # and "libav" does not emit the error.
                address = ("localhost", 6970 + i * 2)
            cmd.append(urlbuild("rtp", formataddr(address)))
            
            if not self._ffmpeg2 and i:
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
                self.requestline = self.requestline.strip()
                (self.command, rest) = self.requestline.split(maxsplit=1)
                rest = rest.rsplit(maxsplit=1)
                if len(rest) >= 2:
                    (self.path, self.request_version) = rest
                else:
                    (self.path,) = rest
                    self.request_version = None
                
                self.plainpath = urlparse(self.path).path
                if self.plainpath == "*":
                    self.plainpath = None
                
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
                self.media = None  # Indicates path not parsed
                self.streams = None  # Indicates media not parsed
                self.sessionparsed = False
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
        allow = {
            METHOD_NOT_ALLOWED,  # Required by specification
            METHOD_NOT_VALID_IN_THIS_STATE,  # Recommended by specification
            
            # Other statuses not suggested by specification
            AGGREGATE_OPERATION_NOT_ALLOWED,
            ONLY_AGGREGATE_OPERATION_ALLOWED,
        }
        if code in allow:
            self.send_allow()
        self.end_headers()
    
    def send_response(self, *pos, **kw):
        self.response_started = True
        BaseHTTPRequestHandler.send_response(self, *pos, **kw)
        for cseq in self.headers.get_all("CSeq", ()):
            self.send_header("CSeq", cseq)
    
    handlers = dict()
    
    @setitem(handlers, "OPTIONS")
    def handle_options(self):
        """
        OPTIONS bad-path -> 404 + Public
        OPTIONS + Session: bad -> 454 + Allow + Public
        OPTIONS * [+ Session] -> 200 + [Session +] Allow + Public
        OPTIONS path [+ Session] -> 200 + [Session +] Allow + Public
        """
        try:
            if self.plainpath:
                self.parse_path()
                self.parse_media()
            try:
                self.parse_session()
                self.send_response(OK)
            except ErrorResponse as err:
                self.send_response(err.code, err.message)
            self.send_allow()
        except ErrorResponse as err:
            self.send_response(err.code, err.message)
        self.send_public()
        self.end_headers()
    
    def handle_request(self):
        msg = 'Request method "{}" not implemented'.format(self.command)
        self.send_response(NOT_IMPLEMENTED, msg)
        self.send_public()
        self.end_headers()
    
    @setitem(handlers, "DESCRIBE")
    def handle_describe(self):
        """
        DESCRIBE * -> 405 + [Session +] Allow
        DESCRIBE bad-path -> 404
        DESCRIBE stream -> 460 + [Session +] Allow
        DESCRIBE path -> 200 + entity
        """
        self.parse_path()
        sdp = self.parse_media()
        if self.stream is not None:
            raise ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        
        self.send_response(OK)
        self.send_header("Content-Type", "application/sdp")
        self.send_header("Content-Length", len(sdp))
        
        location = list()
        encoding = EncodeMap("%#?/")
        for elem in self.media:
            elem = elem.translate(encoding)
            if elem in {".", ".."}:
                elem = "%2E" + elem[1:]
            location.append(elem + "/")
        location = "/" + "".join(location)
        self.send_header("Content-Location", urlbuild(path=location))
        
        self.end_headers()
        self.wfile.write(sdp)
    
    @setitem(handlers, "SETUP")
    def handle_setup(self):
        """
        SETUP + Session: bad -> 454
        SETUP new-path + Session -> 455 + Session + Allow
        SETUP bad-path -> 404
        SETUP + Session: streaming -> 455 + Session + Allow
        SETUP * [+ Session] -> 405 + [Session +] Allow
        SETUP aggregate [+ Session] -> 459 + [Session +] Allow
        SETUP stream [+ Session] + Transport: bad -> 461
        SETUP stream [+ Session] + Transport -> 200 + Session + Transport
        """
        self.parse_session()
        self.parse_session_path()
        if self.session is None:
            session = Session(self.media, self.ospath, self.streams)
        else:
            session = self.session
        
        if self.stream is None:
            if self.streams > 1:
                msg = "{} streams available".format(self.streams)
                raise ErrorResponse(AGGREGATE_OPERATION_NOT_ALLOWED, msg)
            self.stream = 0
        if session.ffmpeg:
            msg = "SETUP not supported while streaming"
            raise ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE, msg)
        
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
        
        dest = self.client_address[0]
        session.addresses[self.stream] = (dest, port)
        if self.session is None:
            self.sessionkey = random.getrandbits(_SESSION_DIGITS * 4)
            self.server._sessions[self.sessionkey] = session
        
        self.send_response(OK)
        self.send_session()
        transport = "RTP/AVP/UDP;unicast;destination={};client_port={}-{}"
        transport = transport.format(dest, port, port + 2 - 1)
        self.send_header("Transport", transport)
        self.end_headers()
    
    @setitem(handlers, "TEARDOWN")
    def handle_teardown(self):
        """
        TEARDOWN new-path + Session -> 455 + Session + Allow
        TEARDOWN bad-path -> 404
        TEARDOWN + Session: bad -> 200 "Session not found"
        TEARDOWN (no Session) -> 454 + Allow
        TEARDOWN * -> 200 "Session invalidated"
        TEARDOWN path/new-stream -> 200 "Not set up"
        TEARDOWN lone-stream -> 200 "Session invalidated"
        TEARDOWN stream + Session: streaming -> 455 + Session + Allow
        TEARDOWN stream + Session: stopped -> 200 + Session
        """
        try:
            self.parse_session()
        except ErrorResponse as err:
            msg = err.message
            if msg is None:
                msg = self.responses.get(err.code)[0]
        if self.plainpath:
            self.parse_session_path()
        else:
            self.stream = None
        if self.invalidsession:
            raise ErrorResponse(OK, msg)
        if not self.session:
            self.send_response(SESSION_NOT_FOUND, "No session given")
            self.send_allow()
            self.end_headers()
            return
        
        if self.stream is None:
            self.server._sessions.pop(self.sessionkey).end()
            msg = "Session invalidated"
        else:
            if (self.session.ffmpeg and
            self.session.other_addresses(stream)):
                msg = "Partial TEARDOWN not supported while streaming"
                raise ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE, msg)
            
            msg = None
            if not self.session.addresses[self.stream]:
                msg = "Stream {} not set up".format(self.stream)
            self.session.addresses[self.stream] = None
            if not any(self.session.addresses):
                self.server._sessions.pop(self.sessionkey).end()
                msg = "Session invalidated"
        self.send_response(OK, msg)
        if self.sessionkey in self.server._sessions:
            self.send_session()
        self.end_headers()
    
    @setitem(handlers, "PLAY")
    def handle_play(self):
        """
        PLAY + Session: bad -> 454
        PLAY new-path -> 455 + Session + Allow
        PLAY bad-path -> 404
        PLAY (no Session) -> 454 + Allow
        PLAY * -> 200 + Session
        PLAY new-stream -> 455 + Session + Allow
        PLAY lone-stream -> 200 + Session
        PLAY stream -> 460 + Session + Allow
        """
        self.parse_session()
        if self.plainpath:
            self.parse_session_path()
        else:
            self.stream = None
        if not self.session:
            self.send_response(SESSION_NOT_FOUND, "No session given")
            self.send_allow()
            self.end_headers()
            return
        if (self.stream is not None and
        self.session.other_addresses(self.stream)):
            raise ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        if self.session.ffmpeg:
            self.send_response(OK, "Already playing")
            self.send_session()
            self.end_headers()
            return
        
        options = ("-re",)
        addresses = self.session.addresses
        streams = ((type, address) for (type, address) in
            zip(self.server._streamtypes, addresses) if address)
        self.session.ffmpeg = self.server._ffmpeg(
            self.session.ospath, options, streams, stdout=subprocess.DEVNULL)
        self.send_response(OK)
        self.send_session()
        self.end_headers()
    
    #~ @setitem(handlers, "PAUSE")
    #~ def handle_pause(self):
        #~ return self.handle_request()
    
    def parse_path(self):
        """Parse path into media path and possible stream number"""
        path = self.plainpath
        if not path:
            msg = "Method {} does not accept null path".format(self.command)
            raise ErrorResponse(METHOD_NOT_ALLOWED, msg)
        
        try:
            if path.startswith("/"):
                path = path[1:]
            self.media = list()
            isdir = True  # Remember if the normal path ends with a slash
            for elem in path.split("/"):
                isdir = True  # Default unless special value not found
                if elem == "..":
                    if self.media:
                        self.media.pop()
                elif elem not in {"", "."}:
                    elem = urllib.parse.unquote(elem,
                        "ascii", "surrogateescape")
                    self.media.append(elem)
                    isdir = False
            if isdir:
                self.stream = None
            else:
                self.stream = int(self.media.pop())
        
        except ValueError as err:
            raise ErrorResponse(NOT_FOUND, err)
    
    def parse_media(self):
        try:
            self.ospath = joinpath(self.media, ".")
            (sdp, self.streams) = self.server._get_sdp(self.ospath)
        except (ValueError, EnvironmentError) as err:
            raise ErrorResponse(NOT_FOUND, err)
        self.validate_stream()
        return sdp
    
    def parse_session_path(self):
        self.parse_path()
        if self.session:
            if self.media != self.session.media:
                msg = "Session already set up with different media file"
                raise ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE, msg)
            self.streams = len(self.session.addresses)
            self.validate_stream()
        else:
            self.parse_media()
    
    def validate_stream(self):
        if (self.stream is not None and
        self.stream not in range(self.streams)):
            msg = "Stream number out of range 0-{}"
            raise ErrorResponse(NOT_FOUND, msg.format(self.streams - 1))
    
    def parse_session(self):
        self.sessionparsed = True
        self.invalidsession = True
        self.session = None  # Indicate no session by default
        key = self.headers.get("Session")
        if key is None:
            self.invalidsession = False
            return
        try:
            self.sessionkey = int(key, 16)
        except ValueError as err:
            raise ErrorResponse(SESSION_NOT_FOUND, err)
        self.session = self.server._sessions.get(self.sessionkey)
        if self.session is None:
            raise ErrorResponse(SESSION_NOT_FOUND)
        self.invalidsession = False
    
    def send_public(self):
        self.send_header("Public", ", ".join(self.handlers.keys()))
    
    def send_allow(self):
        if self.plainpath:
            try:
                if self.media is None:
                    self.parse_path()
                if self.streams is None:
                    self.parse_media()
            except ErrorResponse:
                return
        if not self.sessionparsed:
            try:
                self.parse_session()
            except ErrorResponse:
                pass
        
        mediamatch = (not self.session or not self.plainpath or
            self.session.media == self.media)
        streaming = self.session and self.session.ffmpeg
        allstreams = self.session and (
            not self.plainpath or self.stream is None or
            self.session.addresses[self.stream] and
            not self.session.other_addresses(self.stream)
        )
        
        allow = ["OPTIONS"]
        
        if self.plainpath:
            if self.stream is None:
                allow.append("DESCRIBE")
            
            singlestream = self.stream is not None or self.streams <= 1
            if (mediamatch and singlestream and not self.invalidsession and
            not streaming):
                allow.append("SETUP")
        
        if (self.invalidsession or
        self.session and mediamatch and (allstreams or not streaming)):
            allow.append("TEARDOWN")
        if mediamatch and allstreams:
            allow.append("PLAY")
        
        if self.session:
            self.send_session()
        self.send_header("Allow", ", ".join(allow))
    
    def send_session(self):
        key = format(self.sessionkey, "0{}X".format(_SESSION_DIGITS))
        self.send_header("Session", key)

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
    def __init__(self, media, ospath, streams):
        self.media = media
        self.ospath = ospath
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

class EncodeMap(Mapping):
    surrogates = range(0xDC80, 0xDD00)
    controls = range(0x20 + 1)
    def __init__(self, reserved):
        self.encode = set(map(ord, reserved))
        self.encode.update(map(ord, "<>"))
        self.encode.add(0x7F)
    def __getitem__(self, cp):
        if cp in self.surrogates:
            cp -= 0xDC00
        elif cp not in self.encode and cp not in self.controls:
            raise KeyError()
        return "%{:02X}".format(cp)
    def __len__(self):
        return len(self.reserved) + len(self.surrogates) + len(self.controls)
    def __iter__(self):
        yield from self.encode
        yield from self.controls
        yield from self.surrogates

@attributes(param_types=dict(port=int))
def main(port=RTSP_PORT, *, noffmpeg2=False):
    server = Server(("", port), ffmpeg2=not noffmpeg2)
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
