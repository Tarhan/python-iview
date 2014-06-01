import http.server
from urllib.parse import urlparse
from http.client import (
    REQUEST_URI_TOO_LONG, REQUEST_HEADER_FIELDS_TOO_LARGE,
    METHOD_NOT_ALLOWED, BAD_REQUEST,
)
from http.client import NOT_IMPLEMENTED, INTERNAL_SERVER_ERROR
from http.client import OK
import email.parser
import urllib.parse
from collections.abc import Mapping
from misc import formataddr, urlbuild

class Server(http.server.HTTPServer):
    def __init__(self, address=("", None), RequestHandlerClass=None):
        super().__init__(address, RequestHandlerClass)
        (host, port) = address
        if port is not None:
            port = self.server_port
        self.server_address = formataddr((self.server_name, port))
    
    def handle_error(self, *pos, **kw):
        exc = sys.exc_info()[0]
        if issubclass(exc, ConnectionError):
            return
        if not issubclass(exc, Exception):
            raise  # Force server loop to exit
        super().handle_error(*pos, **kw)
    
    def serve_forever(self, *pos, **kw):
        try:
            super().serve_forever(*pos, **kw)
        finally:
            self.server_close()

class RequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Base-HTTP"
    
    def handle_one_request(self):
        self.close_connection = True
        self.response_started = False
        try:
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
                self.requestline = self.requestline.strip()
                words = self.requestline.split(maxsplit=1)
                if not words:
                    msg = "Missing request method"
                    raise ErrorResponse(BAD_REQUEST, msg)
                self.command = words[0]
                if len(words) < 2:
                    words = ("",)
                else:
                    words = words[1].rsplit(maxsplit=1)
                self.path = words[0]
                if len(words) < 2:
                    self.request_version = None
                else:
                    self.request_version = words[1]
                
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
                self.handle_method()
            
            except ErrorResponse as resp:
                self.send_error(resp.code, resp.message)
        except Exception as err:
            self.server.handle_error(self.request, self.client_address)
            if not self.response_started:
                self.send_error(INTERNAL_SERVER_ERROR, err)
        if self.response_started:
            self.close_connection = True
    
    def handle_method(self):
        handler = getattr(self, "do_" + self.command, self.handle_request)
        handler()
    
    allow_codes = {METHOD_NOT_ALLOWED}  # Required by specification
    
    def send_error(self, code, message=None):
        self.send_response(code, message)
        if self.close_connection:
            self.send_header("Connection", "close")
        if code in self.allow_codes:
            self.send_allow()
        self.end_headers()
    
    def send_response(self, *pos, **kw):
        self.response_started = True
        http.server.BaseHTTPRequestHandler.send_response(self, *pos, **kw)
    
    def end_headers(self, *pos, **kw):
        http.server.BaseHTTPRequestHandler.end_headers(self, *pos, **kw)
        self.response_started = False
    
    def handle_request(self):
        msg = 'Request method "{}" not implemented'.format(self.command)
        self.send_response(NOT_IMPLEMENTED, msg)
        self.send_public()
        self.end_headers()
    
    def send_entity(self, type, location, data):
        self.send_response(OK)
        self.send_header("Content-Type", type)
        self.send_header("Content-Length", len(data))
        
        url = list()
        encoding = EncodeMap("%#?/")
        for elem in location:
            elem = elem.translate(encoding)
            if elem in {".", ".."}:
                elem = "%2E" + elem[1:]
            url.append(elem)
        url = "/" + "/".join(url)
        url = urlbuild(self.scheme, self.server.server_address, url)
        
        # Send Content-Base
        # because many clients (FF MPEG) ignore Content-Location
        self.send_header("Content-Base", url)
        
        self.end_headers()
        self.wfile.write(data)
    
    def parse_path(self):
        path = self.plainpath
        if not path:
            msg = "Method {} does not accept null path".format(self.command)
            raise ErrorResponse(METHOD_NOT_ALLOWED, msg)
        
        if path.startswith("/"):
            path = path[1:]
        self.parsedpath = list()
        emptyfile = ("",)  # Remember if normal path ends with a slash
        for elem in path.split("/"):
            emptyfile = ("",)  # Default unless special value not found
            if elem == "..":
                if self.parsedpath:
                    self.parsedpath.pop()
            elif elem not in {"", "."}:
                elem = urllib.parse.unquote(elem,
                    "ascii", "surrogateescape")
                self.parsedpath.append(elem)
                emptyfile = ()
        self.parsedpath.extend(emptyfile)
    
    def send_public(self):
        methods = list()
        for method in dir(self):
            if method.startswith("do_"):
                methods.append(method[3:])
        self.send_header("Public", ", ".join(methods))

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
