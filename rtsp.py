from calltrace import traced

from http.server import HTTPServer, BaseHTTPRequestHandler
#~ import socketserver
from http.client import REQUEST_URI_TOO_LONG, NOT_IMPLEMENTED, OK
import email.parser, email.message
from functions import setitem
from io import BytesIO

try:  # Python 3.3
    from http.client import REQUEST_HEADER_FIELDS_TOO_LARGE
except ImportError:  # Python < 3.3
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431

RTSP_PORT = 554

UNSUPPORTED_TRANSPORT = 461

#~ class Server(socketserver.ThreadingMixIn, HTTPServer):
    #~ pass
Server = HTTPServer

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
        sdp = (
            b"v=0\r\n"
            b"m=video 0 RTP/AVP 96\r\n"
            b"a=rtpmap:96 H264/90000\r\n"
#~ a=fmtp:96 packetization-mode=1;profile-level-id=4d401f;sprop-parameter-sets=Z01AH5ZzgUBf8uAoEAAA4UAAK/IDRgBDwAKkl73w+EQijw==,aP48gA==;
            b"m=audio 0 RTP/AVP 96\r\n"
            b"a=rtpmap:96 mpeg4-generic/44100/2\r\n"  # OR MP4A-LATM?
#~ a=fmtp:96 streamtype=5; profile-level-id=15; mode=AAC-hbr; config=121056e500; SizeLength=13; IndexLength=3; IndexDeltaLength=3; Profile=1;
        )
        self.send_response(OK)
        self.send_header("Content-Type", "application/sdp")
        self.send_header("Content-Length", len(sdp))
        self.end_headers()
        self.wfile.write(sdp)
    
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

def main(port=RTSP_PORT):
    Server(("", port), Handler).serve_forever()

if __name__ == "__main__":
    from funcparams import command
    command()
