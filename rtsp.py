from calltrace import traced

from http.server import HTTPServer, BaseHTTPRequestHandler
#~ import socketserver
from http.client import REQUEST_URI_TOO_LONG, REQUEST_HEADER_FIELDS_TOO_LARGE
from http.client import NOT_IMPLEMENTED
from http.client import OK
import email.parser, email.message
from functions import setitem
from io import BytesIO
import subprocess
import sys
import random

RTSP_PORT = 554

_SESSION_DIGITS = 25

#~ class Server(socketserver.ThreadingMixIn, HTTPServer):
class Server(HTTPServer):
    def __init__(self, file, address=("", RTSP_PORT)):
        ffmpeg = ("ffmpeg",
            "-loglevel", "warning",
            "-t", "0",  # Stop before processing any video
            "-i", file,
        )
        if False:  # FF MPEG 2.1
            rtp = ("-f", "rtp", "rtp://localhost:1")
            ffmpeg += ("-map", "0:v", "-vcodec", "copy") + rtp
            ffmpeg += ("-map", "0:a", "-acodec", "copy") + rtp
        else:  # libav 0.8.6
            rtp = ("-f", "rtp", "rtp://localhost")
            ffmpeg += ("-vcodec", "copy", "-an") + rtp
            ffmpeg += ("-acodec", "copy", "-vn") + rtp + ("-newaudio",)
        ffmpeg = subprocess.Popen(ffmpeg, stdout=subprocess.PIPE, bufsize=-1)
        with ffmpeg:
            self._sdp = BytesIO()
            line = ffmpeg.stdout.readline()
            
            # FF MPEG unhelpfully adds this prefix to its output
            if line.strip() == b"SDP:":
                line = ffmpeg.stdout.readline()
            
            while line:
                if not line.strip():
                    break
                self._sdp.write(line)
                line = ffmpeg.stdout.readline()
            else:
                with ffmpeg:
                    pass  # Close and wait for process
                msg = "FF MPEG failed generating SDP data; exit status: {}"
                raise EnvironmentError(msg.format(ffmpeg.returncode))
        
        self._sdp = self._sdp.getvalue()
        
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
        
        self.requestline = self.rfile.readline(1000 + 1)
        if not self.requestline:
            return
        if len(self.requestline) > 1000:
            self.send_error(REQUEST_URI_TOO_LONG, "Request line too long")
            return
        
        self.requestline = self.requestline.decode("latin-1").rstrip("\r\n")
        split = self.requestline.split(maxsplit=3)
        self.command, self.path, self.request_version = split[:3]
        
        parser = email.parser.BytesFeedParser(_factory=self.MessageClass)
        for _ in range(200):
            line = self.rfile.readline(1000 + 1)
            if len(line) > 1000:
                msg = "Request header line too long"
                self.send_error(REQUEST_HEADER_FIELDS_TOO_LARGE, msg)
                return
            parser.feed(line)
            if not line.rstrip(b"\r\n"):
                break
        else:
            msg = "Request header too long"
            self.send_error(REQUEST_HEADER_FIELDS_TOO_LARGE, msg)
            return
        self.headers = parser.close()
        
        handler = self.handlers.get(self.command, type(self).handle_request)
        handler(self)
        self.close_connection = False
    
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
        self.send_response(OK)
        self.send_header("Public", ", ".join(self.handlers.keys()))
        self.end_headers()
    
    def handle_request(self):
        msg = 'Request method "{}" not implemented'.format(self.command)
        self.send_error(NOT_IMPLEMENTED, msg)
    
    @setitem(handlers, "DESCRIBE")
    def handle_describe(self):
        self.send_response(OK)
        self.send_header("Content-Type", "application/sdp")
        self.send_header("Content-Length", len(self.server._sdp))
        self.end_headers()
        self.wfile.write(self.server._sdp)
    
    @setitem(handlers, "SETUP")
    def handle_setup(self):
        #~ if self.headers.get_param("interleaved", header="Transport") is None:
            #~ msg = "Only interleaved transport supported"
            #~ self.send_error(UNSUPPORTED_TRANSPORT, msg)
            #~ return
        
        for transports in self.headers.get_all("Transport", ()):
            if '"' in transports:
                continue  # Parsing quotes not implemented
            
            for transport in transports.split(","):
                transport = transport.strip()
                
                params = transport.split(";")
                if params[0].strip() not in {"RTP/AVP", "RTP/AVP/UDP"}:
                    continue
                
                unicast = False
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
                
                else:
                    if unicast:
                        break
            
            else:
                continue
            break
        else:
            self.send_error(UNSUPPORTED_TRANSPORT)
            return
        
        session = self.headers.get("Session")
        if session is None:
            session = random.getrandbits(_SESSION_DIGITS * 4)
        else:
            try:
                session = int(session, 16)
            except ValueError as err:
                self.send_error(SESSION_NOT_FOUND, err)
                return
        
        self.send_response(OK)
        
        session = format(session, "0{}X".format(_SESSION_DIGITS))
        self.send_header("Session", session)
        
        self.send_header("Transport", transport)
        self.end_headers()
    
    handlers["TEARDOWN"] = handle_request
    
    @setitem(handlers, "PLAY")
    def handle_play(self):
        return self.handle_request()
    #~ @setitem(handlers, "PAUSE")
    #~ def handle_pause(self):
        #~ return self.handle_request()

for (code, message) in (
    (454, "Session Not Found"),
    (459, "Aggregate Operation Not Allowed"),
    (460, "Only Aggregate Operation Allowed"),
    (461, "Unsupported Transport"),
):
    symbol = "_".join(message.split()).upper()
    globals()[symbol] = code
    Handler.responses[code] = (message,)

def main(file, port=RTSP_PORT):
    Server(file, ("", port)).serve_forever()

if __name__ == "__main__":
    try:
        from funcparams import command
        command()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
