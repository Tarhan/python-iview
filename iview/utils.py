import zlib
from io import BufferedIOBase, BytesIO, RawIOBase
from urllib.parse import quote_plus
from io import SEEK_CUR, SEEK_END
import urllib.request
import http.client
from errno import EPIPE, ESHUTDOWN, ENOTCONN, ECONNRESET
import selectors
from socketserver import StreamRequestHandler, BaseServer
import sys

try:  # Python 3.3
    ConnectionError
except NameError:  # Python < 3.3
    ConnectionError = ()

DISCONNECTION_ERRNOS = {EPIPE, ESHUTDOWN, ENOTCONN, ECONNRESET}

def xml_text_elements(parent, namespace=""):
    """Extracts text from Element Tree into a dict()
    
    Each key is the tag name of a child of the given parent element, and
    the value is the text of that child. Only tags with no attributes are
    included. If the "namespace" parameter is given, it should specify an
    XML namespace enclosed in curly brackets {. . .}, and only tags in
    that namespace are included."""
    
    d = dict()
    for child in parent:
        if child.tag.startswith(namespace) and not child.keys():
            tag = child.tag[len(namespace):]
            d[tag] = child.text or ""
    return d

def read_int(stream, size):
    bytes = read_strict(stream, size)
    return int.from_bytes(bytes, "big")

def read_string(stream):
    buf = bytearray()
    while True:
        b = read_strict(stream, 1)
        if not ord(b):
            return buf
        buf.extend(b)

def read_strict(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise EOFError()
    return data

value_unsafe = '%+&;#'
VALUE_SAFE = ''.join(chr(c) for c in range(33, 127)
    if chr(c) not in value_unsafe)
def urlencode_param(value):
    """Minimal URL encoding for query parameter"""
    return quote_plus(value, safe=VALUE_SAFE)

class CounterWriter(BufferedIOBase):
    def __init__(self, output):
        self.length = 0
        self.output = output
    def write(self, b):
        self.length += len(b)
        return self.output.write(b)
    def tell(self):
        return self.length

class ZlibDecompressorWriter(BufferedIOBase):
    def __init__(self, output, *pos, buffer_size=0x10000, **kw):
        self.output = output
        self.buffer_size = buffer_size
        self.decompressor = zlib.decompressobj(*pos, **kw)
    def write(self, b):
        while b:
            data = self.decompressor.decompress(b, self.buffer_size)
            self.output.write(data)
            b = self.decompressor.unconsumed_tail
    def close(self):
        self.decompressor.flush()

class TeeWriter(BufferedIOBase):
    def __init__(self, *outputs):
        self.outputs = outputs
    def write(self, b):
        for output in self.outputs:
            output.write(b)

def streamcopy(input, output, length):
    assert length >= 0
    while length:
        chunk = read_strict(input, min(length, 0x10000))
        output.write(chunk)
        length -= len(chunk)

def fastforward(stream, offset):
    assert offset >= 0
    if stream.seekable():
        pos = stream.seek(offset, SEEK_CUR)
        if pos > stream.seek(0, SEEK_END):
            raise EOFError()
        stream.seek(pos)
    else:
        while offset:
            chunk = read_strict(stream, min(offset, 0x10000))
            offset -= len(chunk)

class WritingReader(BufferedIOBase):
    """Filter for a reader stream that writes the data read to another stream
    """
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
    def read(self, n):
        data = self.reader.read(n)
        self.writer.write(data)
        return data

class GeneratorReader(RawIOBase):
    def __init__(self, gen, initial=b""):
        self._gen = gen
        self._pending = initial
    
    def read(self, size):
        if not self._pending:
            self._pending = next(self._gen, b"")
        result = self._pending[:size]
        self._pending = self._pending[size:]
        return result
    
    def close(self):
        self._gen.close()

def setitem(dict, key):
    """Decorator that adds the definition to a dictionary with a given key"""
    def decorator(func):
        dict[key] = func
        return func
    return decorator

class PersistentConnectionHandler(urllib.request.BaseHandler):
    """URL handler for HTTP persistent connections
    
    connection = PersistentConnectionHandler()
    session = urllib.request.build_opener(connection)
    
    # First request opens connection
    with session.open("http://localhost/one") as response:
        response.read()
    
    # Subsequent requests reuse the existing connection, unless it got closed
    with session.open("http://localhost/two") as response:
        response.read()
    
    # Closes old connection when new host specified
    with session.open("http://example/three") as response:
        response.read()
    
    connection.close()  # Frees socket
    
    Currently does not reuse an existing connection if
    two host names happen to resolve to the same Internet address.
    """
    
    def __init__(self, *pos, **kw):
        self._type = None
        self._host = None
        self._pos = pos
        self._kw = kw
        self._connection = None
    
    def default_open(self, req):
        if req.type != "http":
            return None
        
        if req.type != self._type or req.host != self._host:
            if self._connection:
                self._connection.close()
            self._connection = http.client.HTTPConnection(req.host,
                *self._pos, **self._kw)
            self._type = req.type
            self._host = req.host
        
        headers = dict(req.header_items())
        self._attempt_request(req, headers)
        try:
            try:
                response = self._connection.getresponse()
            except EnvironmentError as err:  # Python < 3.3 compatibility
                if err.errno not in DISCONNECTION_ERRNOS:
                    raise
                raise http.client.BadStatusLine(err) from err
        except (ConnectionError, http.client.BadStatusLine):
            idempotents = {
                "GET", "HEAD", "PUT", "DELETE", "TRACE", "OPTIONS"}
            if req.get_method() not in idempotents:
                raise
            # Retry requests whose method indicates they are idempotent
            self._connection.close()
            response = None
        else:
            if response.status == http.client.REQUEST_TIMEOUT:
                # Server indicated it did not handle request
                response = None
        if not response:
            # Retry request
            self._attempt_request(req, headers)
            response = self._connection.getresponse()
        
        # Odd impedance mismatch between "http.client" and "urllib.request"
        response.msg = response.reason
        return response
    
    def _attempt_request(self, req, headers):
        """Send HTTP request, ignoring broken pipe and similar errors"""
        try:
            self._connection.request(req.get_method(), req.selector,
                req.data, headers)
        except (ConnectionRefusedError, ConnectionAbortedError):
            raise  # Assume connection was not established
        except ConnectionError:
            pass  # Continue and read server response if available
        except EnvironmentError as err:  # Python < 3.3 compatibility
            if err.errno not in DISCONNECTION_ERRNOS:
                raise
    
    def close(self):
        if self._connection:
            self._connection.close()
    
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()

def http_get(session, url, types=None, *, headers=dict(), **kw):
    headers = dict(headers)
    if types is not None:
        headers["Accept"] = ", ".join(types)
    req = urllib.request.Request(url, headers=headers, **kw)
    response = session.open(req)
    try:
        headers = response.info()
        headers.set_default_type(None)
        type = headers.get_content_type()
        if types is not None and type not in types:
            msg = "Unexpected content type {}"
            raise TypeError(msg.format(type))
        return response
    except:
        response.close()
        raise

def format_addr(address):
    [address, port] = address
    if not frozenset("[]:").isdisjoint(address):
        address = "[{}]".format(address)
    if port is not None:
        address = "{}:{}".format(address, port)
    return address

def header_list(message, header):
    for header in message.get_all(header, ()):
        yield from header_split(header, ",")

def header_split(header, delim):
    while header:
        [elem, header] = header_partition(header, delim)
        if elem:
            yield elem

def header_partition(header, sep):
    sentinelled = header + sep + '"\\'
    pos = 0
    while True:  # For each quoted segment
        end = sentinelled.index(sep, pos)
        quote = sentinelled.index('"', pos)
        if end < quote:
            break
        pos = quote + 1
        while True:  # For each backslash escape in quote
            quote = sentinelled.index('"', pos)
            backslash = sentinelled.index("\\", pos)
            if quote < backslash:
                break
            pos = min(backslash + 2, len(header))
        pos = min(quote + 1, len(header))
    
    return (header[:end].strip(), header[end + 1:].strip())

class RollbackReader(BufferedIOBase):
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self.readbuffer = BytesIO()
    
    def fileno(self, *pos, **kw):
        return self.wrapped.fileno(*pos, **kw)
    
    def start_capture(self):
        self.writebuffer = BytesIO()
    def drop_capture(self):
        self.writebuffer = None
    def roll_back(self):
        self.readbuffer = self.writebuffer
        self.readbuffer.seek(0)
        self.writebuffer = None
    
    def read(self, size=None):
        data = self.readbuffer.read(size)
        if size is not None and size >= 0:
            size -= len(data)
        data += self.wrapped.read(size)
        if self.writebuffer:
            self.writebuffer.write(data)
        return data

class SelectableServer(BaseServer):
    def handle_error(self, *pos, **kw):
        '''Inhibit reporting of remote connection dropouts'''
        [_, exc, *_] = sys.exc_info()
        if not isinstance(exc, ConnectionError) and (
                not isinstance(exc, EnvironmentError) or
                    exc.errno not in DISCONNECTION_ERRNOS):
            super().handle_error(*pos, **kw)

    def __init__(self, *pos, **kw):
        super().__init__(*pos, **kw)
        self.selector = None
        self.selected = False
        self.handlers = set()
    
    def register(self, selector):
        self.selector = selector
        self.selector.register(self.fileno(), selectors.EVENT_READ,
            self.handle_select)
    
    def handle_select(self):
        self.selected = True
        self.handle_request()
        self.selected = False
    
    def process_request(self, *pos, **kw):
        if not self.selected:
            return super().process_request(*pos, **kw)
        self.finish_request(*pos, **kw)
    
    def server_close(self):
        while self.handlers:
            next(iter(self.handlers)).close()
        if self.selector:
            self.selector.unregister(self.fileno())
        return super().server_close()

class SelectableHandler(StreamRequestHandler):
    def handle(self):
        if not self.server.selected:
            return super().handle()
        self.server.selector.register(self.rfile, selectors.EVENT_READ,
            self.handle_select)
        self.server.handlers.add(self)
    
    def handle_select(self):
        self.close_connection = True
        try:
            self.handle_one_request()
        finally:
            if self.close_connection:
                self.close()
    
    def close(self):
        self.server.handlers.remove(self)
        self.server.selector.unregister(self.rfile)
        self.finish()
        self.server.shutdown_request(self.request)
    
    def finish(self):
        if not self.server.selected:
            return super().finish()

def select_callbacks(selector):
    '''Invokes the selector and then the relevant callbacks'''
    ready = selector.select()
    for [ready, _] in ready:
        if ready.fileobj not in selector.get_map():
            continue  # File unregistered since select() returned
        try:
            ready.data()
        except ConnectionError:
            pass
        except Exception:
            sys.excepthook(*sys.exc_info())
