import basehttp
from http.client import NOT_FOUND, OK
from io import BytesIO, TextIOWrapper
import subprocess
import random
import net
from misc import joinpath
import time
import selectors
import sys
from utils import SelectableServer
from utils import RewindableReader
from socketserver import UDPServer, BaseRequestHandler
from struct import Struct
from urllib.parse import urlencode
import json

_SESSION_DIGITS = 25

class Server(basehttp.Server):
    default_port = 554
    
    def __init__(self, address=("", None), *, ffmpeg2=True):
        """ffmpeg2: Assume FF MPEG 2.1 rather than libav 0.8.6"""
        self._ffmpeg2 = ffmpeg2
        self._sessions = dict()
        super().__init__(address, Handler)
    
    def _get_sdp(self, file):
        options = (
            "-show_entries", "format=duration : format_tags=title",
            "-print_format", "json",
            file,
        )
        with _ffmpeg_command("ffprobe", options, bufsize=-1) as ffprobe, \
        TextIOWrapper(ffprobe.stdout, "ascii") as metadata:
            metadata = json.load(metadata)
        if ffprobe.returncode:
            msg = "ffprobe returned exit status {}"
            raise EnvironmentError(msg.format(ffprobe.returncode))
        notitle = "title" not in metadata["format"].get("tags", dict())
        
        options = ("-t", "0")  # Stop before processing any video
        streams = ((type, None) for type in _streamtypes)
        ffmpeg = _ffmpeg(file, options, streams,
            loglevel="error",  # Avoid empty output warning caused by "-t 0"
            bufsize=-1,
            ffmpeg2=self._ffmpeg2,
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
                if end or line.startswith(b"m="):
                    if streams:  # End of a media section
                        control = "a=control:{}\r\n".format(streams - 1)
                        sdp.write(control.encode("ascii"))
                    else:  # End of the top session-level section
                        range = "a=range:npt=0-{}\r\n"
                        range = range.format(metadata["format"]["duration"])
                        sdp.write(range.encode("ascii"))
                if end:
                    break
                
                if line.startswith(b"m="):
                    fields = line.split(maxsplit=2)
                    PORT = 1
                    fields[PORT] = b"0"  # VLC hangs or times out otherwise
                    line = b" ".join(fields)
                    streams += 1
                if notitle and line.startswith(b"s="):
                    # SDP specification says the session name field must be
                    # present and non-empty, recommending a single space
                    # where there is no name, but players tend to handle
                    # omitting it better
                    line = b""
                
                if not line.startswith(b"a=control:"):
                    sdp.write(line)
                
                line = ffmpeg.stdout.readline()
            else:
                with ffmpeg:
                    pass  # Close and wait for process
                msg = "FF MPEG failed generating SDP data; exit status: {}"
                raise EnvironmentError(msg.format(ffmpeg.returncode))
        return (sdp.getvalue(), streams)
    
    def server_close(self, *pos, **kw):
        while self._sessions:
            (_, session) = self._sessions.popitem()
            session.end()
        return basehttp.Server.server_close(self, *pos, **kw)

_streamtypes = ("video", "audio")

def _ffmpeg(file, options, streams, bufsize=0, ffmpeg2=True, **kw):
    """Spawn an FF MPEG child process
    
    * options: CLI arguments to include
    * streams: Output an RTP stream for each of these
    """
    options = list(options) + ["-i", file]
    
    for (i, (type, addresses)) in enumerate(streams):
        t = type[0]
        if ffmpeg2:
            options.extend(("-map", "0:" + t))
        options.extend(("-{}codec".format(t), "copy"))
        options.extend("-{}n".format(other[0]) for
            other in _streamtypes if other != type)
        
        options.extend(("-f", "rtp", "-rtpflags", "send_bye"))
        query = list()
        if not addresses:
            # Avoid null or zero port because FF MPEG emits an error,
            # although only after outputting the SDP data,
            # and "libav" does not emit the error.
            rtp = ("localhost", 6970 + i * 2)
        else:
            [rtp, rtcp] = addresses
            query.append(("rtcpport", rtcp))
        options.append(net.Url("rtp", net.format_addr(rtp),
            query=urlencode(query)).geturl())
        
        if not ffmpeg2 and i:
            options += ("-new" + type,)
        first = False
    
    return _ffmpeg_command("ffmpeg", options, bufsize=bufsize, **kw)

def _ffmpeg_command(command, options, loglevel="warning", **popenargs):
    command = [command, "-loglevel", loglevel]
    command.extend(options)
    return subprocess.Popen(command,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, **popenargs)

class Handler(basehttp.RequestHandler):
    server_version = "RTSP-server " + basehttp.RequestHandler.server_version
    protocol_version = "RTSP/1.0"
    scheme = "rtsp"
    
    def setup(self):
        basehttp.RequestHandler.setup(self)
        self.rfile = RewindableReader(self.rfile)
    
    def handle_one_request(self):
        self.rfile.capture()
        c = self.rfile.read(1)
        if c == b"$":
            self.rfile.commit()
            raise NotImplementedError("Interleaved packet")
        self.rfile.rewind()
        return basehttp.RequestHandler.handle_one_request(self)
    
    def get_encoding(self, protocol):
        if protocol in {b"RTSP", None}:
            return "utf-8"
        return basehttp.RequestHandler.get_encoding(self, protocol)
    
    def handle_method(self):
        self.media = None  # Indicates path not parsed
        self.streams = None  # Indicates media not parsed
        self.sessionparsed = False
        basehttp.RequestHandler.handle_method(self)
    
    def send_response(self, *pos, **kw):
        basehttp.RequestHandler.send_response(self, *pos, **kw)
        for cseq in self.headers.get_all("CSeq", ()):
            self.send_header("CSeq", cseq)
    
    def do_OPTIONS(self):
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
            except basehttp.ErrorResponse as err:
                self.send_response(err.code, err.message)
            self.send_allow()
        except basehttp.ErrorResponse as err:
            self.send_response(err.code, err.message)
        self.send_public()
        self.end_headers()
    
    def do_DESCRIBE(self):
        """
        DESCRIBE * -> 405 + [Session +] Allow
        DESCRIBE bad-path -> 404
        DESCRIBE stream -> 460 + [Session +] Allow
        DESCRIBE path -> 200 + entity
        """
        self.parse_path()
        sdp = self.parse_media()
        if self.stream is not None:
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        self.send_entity("application/sdp", tuple(self.media) + ("",), sdp)
    
    def do_SETUP(self):
        """
        SETUP + Session: bad -> 454
        SETUP new-path + Session -> 455 + Session + Allow
        SETUP bad-path -> 404
        SETUP + Session: streaming -> 455 + Session + Allow
        SETUP * (no Session) -> 455 + Allow
        SETUP aggregate [+ Session] -> 459 + [Session +] Allow
        SETUP stream [+ Session] + Transport: bad -> 461
        SETUP stream [+ Session] + Transport -> 200 + Session + Transport
        """
        self.parse_session()
        self.parse_session_path()
        if self.session is None:
            if not self.plainpath:
                msg = "No media or session specified"
                raise basehttp.ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE,
                    msg)
            session = Session(self.media, self.ospath, self.streams)
        else:
            session = self.session
        
        if self.stream is None:
            if self.streams > 1:
                msg = "{} streams available".format(self.streams)
                raise basehttp.ErrorResponse(AGGREGATE_OPERATION_NOT_ALLOWED,
                    msg)
            self.stream = 0
        if session.ffmpeg:
            msg = "SETUP not supported while streaming"
            raise basehttp.ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE, msg)
        
        error = None
        for transport in net.header_list(self.headers, "Transport"):
            try:
                [transport, params] = net.header_partition(transport, ";")
                transport = iter(net.header_split(transport, "/"))
                if (next(transport, "RTP").upper() != "RTP" or
                next(transport, "AVP").upper() != "AVP"):
                    raise ValueError("Only RTP/AVP supported")
                
                params = net.HeaderParams(params)
                for mode in params["mode"]:
                    mode = net.header_split(net.header_unquote(mode), ",")
                    if frozenset(map(str.upper, mode)) != {"PLAY"}:
                        raise ValueError("Only mode=PLAY supported")
                
                try:
                    channel = params.get_single("interleaved")
                    transport = InterleavedTransport(self, channel)
                    break
                except KeyError:
                    pass
                
                udp = next(transport, "UDP").upper() == "UDP"
                if udp and "unicast" in params:
                    transport = UdpTransport(self, params)
                    break
                
                msg = ("Only unicast UDP and interleaved transports "
                    "supported")
                raise ValueError(msg)
            except (ValueError, KeyError) as exc:
                multierror = error
                error = format(exc)
        else:  # No suitable transport found
            if not error or multierror:
                error = ("No supported unicast UDP or interleaved transport "
                    "given")
            raise basehttp.ErrorResponse(UNSUPPORTED_TRANSPORT, error)
        
        session.transports[self.stream] = transport
        if self.session is None:
            self.sessionkey = random.getrandbits(_SESSION_DIGITS * 4)
            self.server._sessions[self.sessionkey] = session
            msg = "Session created"
        else:
            msg = None
        
        self.send_response(OK, msg)
        self.send_session()
        self.send_header("Transport", transport.header())
        self.end_headers()
    
    def do_TEARDOWN(self):
        """
        TEARDOWN new-path + Session -> 455 + Session + Allow
        TEARDOWN bad-path -> 404
        TEARDOWN + Session: bad -> 200 "Session not found"
        TEARDOWN (no Session) -> 454 + Allow
        TEARDOWN path/new-stream -> 200 "Not set up"
        TEARDOWN lone-stream -> 200 "Session invalidated"
        TEARDOWN stream + Session: streaming -> 455 + Session + Allow
        TEARDOWN stream + Session: stopped -> 200 + Session
        """
        try:
            self.parse_session()
        except basehttp.ErrorResponse as err:
            msg = err.message
            if msg is None:
                msg = self.responses.get(err.code)[0]
        self.parse_session_path()
        if self.invalidsession:
            raise basehttp.ErrorResponse(OK, msg)
        if not self.session:
            self.send_response(SESSION_NOT_FOUND, "No session given")
            self.send_allow()
            self.end_headers()
            return
        
        if self.stream is None:
            session = self.server._sessions.pop(self.sessionkey)
            msg = "FF MPEG exit status {}".format(session.end())
        else:
            if (self.session.ffmpeg and
            self.session.other_transports(stream)):
                msg = "Partial TEARDOWN not supported while streaming"
                raise basehttp.ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE,
                    msg)
            
            msg = None
            if not self.session.transports[self.stream]:
                msg = "Stream {} not set up".format(self.stream)
            self.session.transports[self.stream] = None
            if not any(self.session.transports):
                session = self.server._sessions.pop(self.sessionkey)
                msg = "FF MPEG exit status {}".format(session.end())
        self.send_response(OK, msg)
        if self.sessionkey in self.server._sessions:
            self.send_session()
        self.end_headers()
    
    def do_PLAY(self):
        """
        PLAY + Session: bad -> 454
        PLAY new-path -> 455 + Session + Allow
        PLAY bad-path -> 404
        PLAY (no Session) -> 454 + Allow
        PLAY new-stream -> 455 + Session + Allow
        PLAY lone-stream -> 200 + Session
        PLAY stream -> 460 + Session + Allow
        """
        self.parse_session()
        self.parse_session_path()
        if not self.session:
            self.send_response(SESSION_NOT_FOUND, "No session given")
            self.send_allow()
            self.end_headers()
            return
        if (self.stream is not None and
        self.session.other_transports(self.stream)):
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        if self.session.ffmpeg:
            self.send_response(OK, "Already playing")
            self.send_session()
            self.end_headers()
            return
        
        try:
            ranges = iter(net.header_list(self.headers, "Range"))
            range = next(ranges, None)
            if range:
                if next(ranges, None):
                    raise ValueError("Only single play range supported")
                range = net.HeaderParams(range)
                if "time" in range:
                    raise ValueError("Start time parameter not supported")
                npt = range.get_single("npt")
                [npt, end] = net.header_partition(npt, "-")
        except KeyError:  # Missing "npt" parameter
            self.send_response(NOT_IMPLEMENTED, "Only NPT range supported")
            self.send_header("Accept-Ranges", "npt")
            self.end_headers()
            return
        except ValueError as err:
            raise basehttp.ErrorResponse(
                HEADER_FIELD_NOT_VALID_FOR_RESOURCE, err)
        
        self.session.start(self.server.selector,
            ffmpeg2=self.server._ffmpeg2)
        self.send_response(OK)
        self.send_session()
        self.end_headers()
    
    def do_PAUSE(self):
        self.parse_session()
        self.parse_session_path()
        if not self.session:
            self.send_response(SESSION_NOT_FOUND, "No session given")
            self.send_allow()
            self.end_headers()
            return
        if (self.stream is not None and
        self.session.other_transports(self.stream)):
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        
        if "Range" in self.headers:
            msg = "Deferred pausing not supported"
            raise basehttp.ErrorResponse(HEADER_FIELD_NOT_VALID_FOR_RESOURCE,
                msg)
        
        if self.session.ffmpeg:
            self.session.pause_point += time.monotonic() - self.session.started
            msg = "FF MPEG exit status {}".format(self.session.end())
            self.session.ffmpeg = None
        else:
            msg = "Already paused"
        self.send_response(OK, msg)
        self.send_session()
        self.end_headers()
    
    def parse_path(self):
        """Parse path into media path and possible stream number"""
        basehttp.RequestHandler.parse_path(self)
        self.media = self.parsedpath[:-1]
        stream = self.parsedpath[-1]
        if stream:
            try:
                self.stream = int(stream)
            except ValueError as err:
                raise basehttp.ErrorResponse(NOT_FOUND, err)
        else:
            self.stream = None
    
    def parse_media(self):
        try:
            self.ospath = joinpath(self.media, ".")
            (sdp, self.streams) = self.server._get_sdp(self.ospath)
        except (ValueError, EnvironmentError,
        subprocess.CalledProcessError) as err:
            raise basehttp.ErrorResponse(NOT_FOUND, err)
        self.validate_stream()
        return sdp
    
    def parse_session_path(self):
        if not self.plainpath:
            self.stream = None
            return
        self.parse_path()
        if self.session:
            if self.media != self.session.media:
                msg = "Session already set up with different media file"
                raise basehttp.ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE,
                    msg)
            self.streams = len(self.session.transports)
            self.validate_stream()
        else:
            self.parse_media()
    
    def validate_stream(self):
        if (self.stream is not None and
        self.stream not in range(self.streams)):
            msg = "Stream number out of range 0-{}".format(self.streams - 1)
            raise basehttp.ErrorResponse(NOT_FOUND, msg)
    
    def parse_session(self):
        self.sessionparsed = True
        self.invalidsession = True
        self.session = None  # Indicate no session by default
        sessions = iter(net.header_list(self.headers, "Session"))
        key = next(sessions, None)
        if not key:
            self.invalidsession = False
            return
        try:
            if next(sessions, None):
                raise ValueError("More than one session given")
            [key, _] = net.header_partition(key, ";")
            self.sessionkey = int(net.header_unquote(key), 16)
        except ValueError as err:
            raise basehttp.ErrorResponse(SESSION_NOT_FOUND, err)
        self.session = self.server._sessions.get(self.sessionkey)
        if self.session is None:
            raise basehttp.ErrorResponse(SESSION_NOT_FOUND)
        self.invalidsession = False
    
    def send_allow(self):
        if self.plainpath:
            try:
                if self.media is None:
                    self.parse_path()
                if self.streams is None:
                    self.parse_media()
            except basehttp.ErrorResponse:
                return
        if not self.sessionparsed:
            try:
                self.parse_session()
            except basehttp.ErrorResponse:
                pass
        
        mediamatch = (not self.session or not self.plainpath or
            self.session.media == self.media)
        streaming = self.session and self.session.ffmpeg
        allstreams = self.session and (
            not self.plainpath or self.stream is None or
            self.session.transports[self.stream] and
            not self.session.other_transports(self.stream)
        )
        
        allow = ["OPTIONS"]
        
        if self.plainpath:
            if self.stream is None:
                allow.append("DESCRIBE")
            
            singlestream = self.stream is not None or self.streams <= 1
        else:
            singlestream = self.session and len(self.session.transports) <= 1
        if (mediamatch and singlestream and not self.invalidsession and
        not streaming):
            allow.append("SETUP")
        
        if (self.invalidsession or
        self.session and mediamatch and (allstreams or not streaming)):
            allow.append("TEARDOWN")
        if mediamatch and allstreams:
            allow.extend(("PLAY", "PAUSE"))
        
        if self.session:
            self.send_session()
        self.send_header("Allow", ", ".join(allow))
    
    def send_session(self):
        key = "{:0{}X};timeout=86400"
        key = key.format(self.sessionkey, _SESSION_DIGITS)
        self.send_header("Session", key)

Handler.responses = dict(Handler.responses)  # Copy from base class
for (code, message) in (
    (454, "Session Not Found"),
    (455, "Method Not Valid In This State"),
    (456, "Header Field Not Valid for Resource"),
    (459, "Aggregate Operation Not Allowed"),
    (460, "Only Aggregate Operation Allowed"),
    (461, "Unsupported Transport"),
):
    symbol = "_".join(message.split()).upper()
    globals()[symbol] = code
    Handler.responses[code] = (message,)

Handler.allow_codes = Handler.allow_codes | {
    METHOD_NOT_VALID_IN_THIS_STATE,  # Recommended by specification
    
    # Other statuses not suggested by specification
    AGGREGATE_OPERATION_NOT_ALLOWED,
    ONLY_AGGREGATE_OPERATION_ALLOWED,
}

class Session:
    def __init__(self, media, ospath, streams):
        self.media = media
        self.ospath = ospath
        self.transports = [None] * streams
        self.ffmpeg = None
        self.pause_point = 0
    
    def start(self, selector, ffmpeg2=True):
        options = ("-re",)
        transports = zip(_streamtypes, self.transports)
        streams = list()
        for [type, transport] in transports:
            if transport:
                streams.append((type, transport.setup()))
        self.ffmpeg = _ffmpeg(self.ospath, options, streams, ffmpeg2=ffmpeg2)
        self.selector = selector
        self.selector.register(self.ffmpeg.stdout, selectors.EVENT_READ,
            self)
        self.started = time.monotonic()
    
    def end(self):
        if self.ffmpeg:
            self.close_transports()
            self.ffmpeg.terminate()
            return self.ffmpeg.wait()
    
    def handle_select(self):
        if not self.ffmpeg.stdout.read(0x10000):
            self.close_transports()
    
    def close_transports(self):
        if not self.ffmpeg.stdout.closed:
            self.selector.unregister(self.ffmpeg.stdout)
            self.ffmpeg.stdout.close()
            for transport in self.transports:
                if transport:
                    transport.close()
    
    def other_transports(self, stream):
        return (any(self.transports[:stream]) or
            any(self.transports[stream + 1:]))

class Transport:
    def close(self):
        pass

class UdpTransport(Transport):
    def __init__(self, handler, params):
        port = params.get_single("client_port")
        [port, end] = net.header_partition(port, "-")
        self.port = int(net.header_unquote(port))
        if end and int(net.header_unquote(end)) < self.port + 1:
            raise ValueError("Pair of ports required for RTP and RTCP")
        
        [self.dest, _] = handler.client_address
    
    def header(self):
        header = "RTP/AVP/UDP;unicast;destination={};client_port={}-{}"
        return header.format(self.dest, self.port, self.port + 1)
    
    def setup(self):
        return ((self.dest, self.port), self.port + 1)

class InterleavedTransport(Transport):
    def __init__(self, handler, channel):
        [channel, end] = net.header_partition(channel, "-")
        self.channel = int(net.header_unquote(channel))
        if end and int(net.header_unquote(end)) < self.channel + 1:
            raise ValueError("Pair of channels required for RTP and RTCP")
        
        self.handler = handler
    
    def header(self):
        header = "RTP/AVP/TCP;interleaved={}-{}"
        return header.format(self.channel, self.channel + 1)
    
    def setup(self):
        self.rtp = UdpListener(self.handler.wfile, self.channel)
        self.rtp.register(self.handler.server.selector)
        self.rtcp = UdpListener(self.handler.wfile, self.channel + 1)
        self.rtcp.register(self.handler.server.selector)
        [_, rtcp] = self.rtcp.server_address
        return (self.rtp.server_address, rtcp)
    
    def close(self):
        self.rtcp.close()
        self.rtp.close()

class UdpListener(SelectableServer, UDPServer):
    def __init__(self, file, channel):
        self.file = file
        self.channel = channel
        SelectableServer.__init__(self,
            RequestHandlerClass=InterleavedHandler)

class InterleavedHandler(BaseRequestHandler):
    header = Struct("!cBH")
    def handle(self):
        [packet, _] = self.request
        header = self.header.pack(b"$", self.server.channel, len(packet))
        self.server.file.write(header)
        self.server.file.write(packet)
        self.server.file.flush()

def main(address="", *, noffmpeg2=False):
    with selectors.DefaultSelector() as selector, \
    Server(net.parse_addr(address), ffmpeg2=not noffmpeg2) as server:
        print(server.server_address)
        server.register(selector)
        while True:
            ready = selector.select()
            for [ready, _] in ready:
                try:
                    ready.data.handle_select()
                except ConnectionError:
                    pass
                except Exception:
                    sys.excepthook(*sys.exc_info())

if __name__ == "__main__":
    try:
        import clifunc
        clifunc.run()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
