#~ import socketserver
import basehttp
from http.client import NOT_FOUND, OK
from functions import setitem
from io import BytesIO
import subprocess
import random
from functions import attributes
from misc import formataddr, urlbuild
from misc import joinpath

_SESSION_DIGITS = 25

#~ class Server(socketserver.ThreadingMixIn, basehttp.Server):
class Server(basehttp.Server):
    default_port = 554
    
    def __init__(self, address=("", None), *, ffmpeg2=True):
        """ffmpeg2: Assume FF MPEG 2.1 rather than libav 0.8.6"""
        self._ffmpeg2 = ffmpeg2
        self._sessions = dict()
        super().__init__(address, Handler)
    
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
    
    def server_close(self, *pos, **kw):
        while self._sessions:
            (_, session) = self._sessions.popitem()
            session.end()
        return basehttp.Server.server_close(self, *pos, **kw)
    
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

class Handler(basehttp.RequestHandler):
    server_version = "RTSP-server " + basehttp.RequestHandler.server_version
    protocol_version = "RTSP/1.0"
    scheme = "rtsp"
    
    def handle_method(self):
        self.media = None  # Indicates path not parsed
        self.streams = None  # Indicates media not parsed
        self.sessionparsed = False
        basehttp.RequestHandler.handle_method(self)
    
    def send_response(self, *pos, **kw):
        basehttp.RequestHandler.send_response(self, *pos, **kw)
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
            except basehttp.ErrorResponse as err:
                self.send_response(err.code, err.message)
            self.send_allow()
        except basehttp.ErrorResponse as err:
            self.send_response(err.code, err.message)
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
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        self.send_entity("application/sdp", tuple(self.media) + ("",), sdp)
    
    @setitem(handlers, "SETUP")
    def handle_setup(self):
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
        for transports in self.headers.get_all("Transport", ()):
            if '"' in transports:
                multierror = error
                error = "Parsing quotes not implemented"
                continue
            
            for transport in transports.split(","):
                try:
                    transport = transport.strip()
                    
                    params = transport.split(";")
                    spec = params[0].strip().upper().split("/", 2)
                    if spec[:2] != ["RTP", "AVP"]:
                        raise ValueError("Only RTP/AVP supported")
                    udp = len(spec) <= 2 or spec[2] == "UDP"
                    
                    unicast = False
                    port = None
                    interleaved = None
                    ilstart = None
                    for param in params[1:]:
                        (name, _, value) = param.partition("=")
                        name = name.strip()
                        value = value.strip()
                        lname = name.lower()
                        
                        unicast = unicast or lname == "unicast" and not value
                        if (lname == "mode" and value and
                        frozenset((value.upper(),)) != {"PLAY"}):  # TODO: parse comma-separated list
                            raise ValueError("Only mode=PLAY supported")
                        
                        if lname == "interleaved":
                            interleaved = True
                            if ilstart is not None:
                                msg = 'Multiple "interleaved" parameters'
                                raise ValueError(msg)
                            (ilstart, _, end) = value.partition("-")
                            ilstart = int(ilstart)
                            if end and int(end) != ilstart + 1:
                                msg = "Only pair of channels supported"
                                raise ValueError(msg)
                        
                        if lname == "client_port" and value:
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
            raise basehttp.ErrorResponse(UNSUPPORTED_TRANSPORT, error)
        
        dest = self.client_address[0]
        session.addresses[self.stream] = (dest, port)
        if self.session is None:
            self.sessionkey = random.getrandbits(_SESSION_DIGITS * 4)
            self.server._sessions[self.sessionkey] = session
            msg = "Session created"
        else:
            msg = None
        
        self.send_response(OK, msg)
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
            self.server._sessions.pop(self.sessionkey).end()
            msg = "Session invalidated"
        else:
            if (self.session.ffmpeg and
            self.session.other_addresses(stream)):
                msg = "Partial TEARDOWN not supported while streaming"
                raise basehttp.ErrorResponse(METHOD_NOT_VALID_IN_THIS_STATE,
                    msg)
            
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
        self.session.other_addresses(self.stream)):
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
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
        except (ValueError, EnvironmentError) as err:
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
            self.streams = len(self.session.addresses)
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
        key = self.headers.get("Session")
        if key is None:
            self.invalidsession = False
            return
        try:
            self.sessionkey = int(key, 16)
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
            self.session.addresses[self.stream] and
            not self.session.other_addresses(self.stream)
        )
        
        allow = ["OPTIONS"]
        
        if self.plainpath:
            if self.stream is None:
                allow.append("DESCRIBE")
            
            singlestream = self.stream is not None or self.streams <= 1
        else:
            singlestream = self.session and len(self.session.addresses) <= 1
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

Handler.responses = dict(Handler.responses)  # Copy from base class
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
        self.addresses = [None] * streams
        self.ffmpeg = None
    
    def end(self):
        if self.ffmpeg:
            self.ffmpeg.terminate()
            self.ffmpeg.wait()
    
    def other_addresses(self, stream):
        return (any(self.addresses[:stream]) or
            any(self.addresses[stream + 1:]))

@attributes(param_types=dict(port=int))
def main(port=None, *, noffmpeg2=False):
    server = Server(("", port), ffmpeg2=not noffmpeg2)
    server.serve_forever()

if __name__ == "__main__":
    try:
        from funcparams import command
        command()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
