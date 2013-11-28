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

#~ FFMPEG_2 = True  # FF MPEG 2.1
FFMPEG_2 = False  # libav 0.8.6

RTSP_PORT = 554

_SESSION_DIGITS = 25

#~ class Server(socketserver.ThreadingMixIn, HTTPServer):
class Server(HTTPServer):
    def __init__(self, file, address=("", RTSP_PORT)):
        ffmpeg = ["ffmpeg", "-loglevel", "warning",
            "-t", "0",  # Stop before processing any video
            "-i", file,
        ]
        if FFMPEG_2:
            rtp = ("-f", "rtp", "rtp://localhost:1")
            ffmpeg.extend(("-map", "0:v", "-vcodec", "copy") + rtp)
            ffmpeg.extend(("-map", "0:a", "-acodec", "copy") + rtp)
        else:
            rtp = ("-f", "rtp", "rtp://localhost")
            ffmpeg.extend(("-vcodec", "copy", "-an") + rtp)
            ffmpeg.extend(("-acodec", "copy", "-vn") + rtp + ("-newaudio",))
        ffmpeg = subprocess.Popen(ffmpeg, stdout=subprocess.PIPE, bufsize=-1)
        with ffmpeg:
            self._sdp = BytesIO()
            line = ffmpeg.stdout.readline()
            
            # FF MPEG unhelpfully adds this prefix to its output
            if line.strip() == b"SDP:":
                line = ffmpeg.stdout.readline()
            
            self._streams = 0
            while line:
                if not line.strip():
                    break
                if not line.startswith(b"a=control:"):
                    self._sdp.write(line)
                
                if line.startswith(b"m="):
                    line = "a=control:{}\r\n".format(self._streams)
                    self._streams += 1
                    self._sdp.write(line.encode("ascii"))
                
                line = ffmpeg.stdout.readline()
            else:
                with ffmpeg:
                    pass  # Close and wait for process
                msg = "FF MPEG failed generating SDP data; exit status: {}"
                raise EnvironmentError(msg.format(ffmpeg.returncode))
        
        self._sdp = self._sdp.getvalue()
        self._sessions = dict()
        
        HTTPServer.__init__(self, address, Handler)
    
    def handle_error(*pos, **kw):
        exc = sys.exc_info()[0]
        if issubclass(exc, ConnectionError):
            return
        if not issubclass(exc, Exception):
            raise  # Force server loop to exit
        HTTPServer.handle_error(*pos, **kw)

class Handler(BaseHTTPRequestHandler):
    protocol_version = "RTSP/1.0"
    responses = dict(BaseHTTPRequestHandler.responses)  # Extended below
    
    def handle_one_request(self):
        self.close_connection = True
        self.request_version = None
        self.headers = self.MessageClass()
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
            
            parser = email.parser.BytesFeedParser(_factory=self.MessageClass)
            for _ in range(200):
                line = self.rfile.readline(1000 + 1)
                if len(line) > 1000:
                    msg = "Request header line too long"
                    raise ErrorResponse(REQUEST_HEADER_FIELDS_TOO_LARGE, msg)
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
            self.close_connection = True
            self.server.handle_error(self.request, self.client_address)
            self.send_error(INTERNAL_SERVER_ERROR, err)
    
    def send_error(self, code, message=None):
        self.send_response(code, message)
        self.end_headers()
    
    def send_response(self, *pos, **kw):
        BaseHTTPRequestHandler.send_response(self, *pos, **kw)
        for cseq in self.headers.get_all("CSeq", ()):
            self.send_header("CSeq", cseq)
    
    def send_header(self, name, value, *pos, **kw):
        return BaseHTTPRequestHandler.send_header(self, name, value, *pos, **kw)
    
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
        self.send_header("Public", ", ".join(self.handlers.keys()))
        self.end_headers()
    
    def handle_request(self):
        msg = 'Request method "{}" not implemented'.format(self.command)
        raise ErrorResponse(NOT_IMPLEMENTED, msg)
    
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
            raise ErrorResponse(AGGREGATE_OPERATION_NOT_ALLOWED)
        
        #~ if self.headers.get_param("interleaved", header="Transport") is None:
            #~ msg = "Only interleaved transport supported"
            #~ raise ErrorResponse(UNSUPPORTED_TRANSPORT, msg)
        
        for transports in self.headers.get_all("Transport", ()):
            if '"' in transports:
                continue  # Parsing quotes not implemented
            
            for transport in transports.split(","):
                transport = transport.strip()
                
                params = transport.split(";")
                if params[0].strip() not in {"RTP/AVP", "RTP/AVP/UDP"}:
                    continue
                
                unicast = False
                port = None
                for param in params[1:]:
                    (name, _, value) = param.partition("=")
                    name = name.strip()
                    value = value.strip()
                    
                    unicast = unicast or name == "unicast" and not value
                    if (
                        name == "mode" and value and
                        frozenset((value,)) != {"PLAY"}  # TODO: parse comma-separated list
                    or name == "interleaved"):
                        break
                    
                    if name == "client_port" and value:
                        if port:
                            break
                        (port, _, end) = value.partition("-")
                        try:
                            port = int(port)
                            if end and int(end) != port + 1:
                                break
                        except ValueError:
                            break
                
                else:
                    if unicast:
                        break
            
            else:
                continue
            break
        else:
            raise ErrorResponse(UNSUPPORTED_TRANSPORT)
        
        if key is None:
            key = random.getrandbits(_SESSION_DIGITS * 4)
            self.server._sessions[key] = session
        session[stream] = (self.client_address[0], port)
        
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
            del self.server._sessions[key]
        else:
            if not session[stream]:
                msg = "Stream {} not set up".format(stream)
                self.send_invalidstate(key, session, stream, msg)
                return
            # TODO: cannot allow single stream op if playing multiple streams
            
            session[stream] = None
            if not any(session):
                del self.server._sessions[key]
        
        self.send_response(OK)
        if key in self.server._sessions:
            self.send_session(key)
        self.end_headers()
    
    @setitem(handlers, "PLAY")
    def handle_play(self):
        (key, session) = self.get_session()
        if not key:
            raise ErrorResponse(SESSION_NOT_FOUND, "No session given")
        stream = self.parse_stream()
        if stream is not None:
            if not session[stream]:
                msg = "Stream {} not set up".format(stream)
                self.send_invalidstate(key, session, stream, msg)
                return
            if any(session[:stream]) or any(session[stream + 1:]):
                raise ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        
        return self.handle_request()
    
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
            return (None, [None] * self.server._streams)
        try:
            key = int(key, 16)
        except ValueError as err:
            raise ErrorResponse(SESSION_NOT_FOUND, err)
        session = self.server._sessions.get(key)
        if session is None:
            raise ErrorResponse(SESSION_NOT_FOUND)
        return (key, session)
    
    def send_allow(self, session_key, session, stream):
        allow = ["OPTIONS"]
        if stream is None:
            allow.append("DESCRIBE")
        else:
            allow.append("SETUP")
        if session_key is not None and (stream is None or session[stream]):
            allow.append("TEARDOWN")
            if (stream is None or
            not any(session[:stream]) and not any(session[stream + 1:])):
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

class ErrorResponse(Exception):
    def __init__(self, code, message=None):
        self.code = code
        self.message = message
        Exception.__init__(self, self.code)

def main(file, port=RTSP_PORT):
    Server(file, ("", port)).serve_forever()

if __name__ == "__main__":
    try:
        from funcparams import command
        command()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
