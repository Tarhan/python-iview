from calltrace import traced

from http.server import HTTPServer, BaseHTTPRequestHandler
#~ import socketserver
from http.client import REQUEST_URI_TOO_LONG, NOT_IMPLEMENTED, OK
import email.parser, email.message
from functions import setitem
from io import BytesIO
import subprocess

try:  # Python 3.3
    from http.client import REQUEST_HEADER_FIELDS_TOO_LARGE
except ImportError:  # Python < 3.3
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431

RTSP_PORT = 554

UNSUPPORTED_TRANSPORT = 461

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

class Handler(BaseHTTPRequestHandler):
    protocol_version = "RTSP/1.0"
    
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
        if self.headers.get_param("interleaved", header="Transport") is None:
            msg = "Only interleaved transport supported"
            self.send_error(UNSUPPORTED_TRANSPORT, msg)
            return
        
        self.send_response(OK)
        for header in self.headers.get_all("Transport", ()):
            self.send_header("Transport", header)
        self.end_headers()
    
    handlers["TEARDOWN"] = handle_request
    
    @setitem(handlers, "PLAY")
    def handle_play(self):
        return self.handle_request()
    #~ @setitem(handlers, "PAUSE")
    #~ def handle_pause(self):
        #~ return self.handle_request()

def main(file, port=RTSP_PORT):
    Server(file, ("", port)).serve_forever()

if __name__ == "__main__":
    from funcparams import command
    command()
