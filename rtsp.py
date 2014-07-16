#~ import socketserver
import basehttp
from http.client import NOT_FOUND, OK
from io import BytesIO
import subprocess
import random
from functions import attributes
import net
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
        options = (
            "-show_entries", "format=duration",
            "-print_format", "compact=print_section=0:nokey=1:escape=none",
            file,
        )
        with self._ffmpeg_command("ffprobe", options,
        stdout=subprocess.PIPE, bufsize=-1) as ffprobe:
            duration = ffprobe.stdout.read().strip()
        if ffprobe.returncode:
            msg = "ffprobe returned exit status {}"
            raise EnvironmentError(msg.format(ffprobe.returncode))
        
        options = ("-t", "0")  # Stop before processing any video
        streams = ((type, None) for type in self._streamtypes)
        ffmpeg = self._ffmpeg(file, options, streams,
            loglevel="error",  # Avoid empty output warning caused by "-t 0"
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
                if end or line.startswith(b"m="):
                    if streams:  # End of a media section
                        control = "a=control:{}\r\n".format(streams - 1)
                        sdp.write(control.encode("ascii"))
                    else:  # End of the top session-level section
                        sdp.write(b"a=range:npt=0-" + duration + b"\r\n")
                if end:
                    break
                
                if line.startswith(b"m="):
                    fields = line.split(maxsplit=2)
                    PORT = 1
                    fields[PORT] = b"0"  # VLC hangs or times out otherwise
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
    
    def _ffmpeg(self, file, options, streams, **kw):
        """Spawn an FF MPEG child process
        
        * options: CLI arguments to include
        * streams: Output an RTP stream for each of these
        """
        options = list(options) + ["-i", file]
        
        for (i, (type, address)) in enumerate(streams):
            t = type[0]
            if self._ffmpeg2:
                options.extend(("-map", "0:" + t))
            options.extend(("-{}codec".format(t), "copy"))
            options.extend("-{}n".format(other[0]) for
                other in self._streamtypes if other != type)
            
            options.extend(("-f", "rtp"))
            if not address:
                # Avoid null or zero port because FF MPEG emits an error,
                # although only after outputting the SDP data,
                # and "libav" does not emit the error.
                address = ("localhost", 6970 + i * 2)
            options.append(net.Url("rtp", net.formataddr(address)).geturl())
            
            if not self._ffmpeg2 and i:
                options += ("-new" + type,)
            first = False
        
        return self._ffmpeg_command("ffmpeg", options, **kw)
    
    def _ffmpeg_command(self, command, options,
    loglevel="warning", **popenargs):
        command = [command, "-loglevel", loglevel]
        command.extend(options)
        return subprocess.Popen(command, **popenargs)

class Handler(basehttp.RequestHandler):
    server_version = "RTSP-server " + basehttp.RequestHandler.server_version
    protocol_version = "RTSP/1.0"
    scheme = "rtsp"
    
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
                    [channel, end] = net.header_partition(channel, "-")
                    channel = int(net.header_unquote(channel))
                    if end and int(net.header_unquote(end)) != channel + 1:
                        raise ValueError("Only pair of channels supported")
                    
                    msg = "Interleaved transport not yet implemented"
                    raise ValueError(msg)
                except KeyError:
                    pass
                
                udp = next(transport, "UDP").upper() == "UDP"
                if udp and "unicast" in params:
                    port = params.get_single("client_port")
                    [port, end] = net.header_partition(port, "-")
                    port = int(net.header_unquote(port))
                    if end and int(net.header_unquote(end)) != port + 1:
                        raise ValueError("Only pair of ports supported")
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
        self.session.other_addresses(self.stream)):
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
        
        options = ("-re",)
        addresses = self.session.addresses
        streams = ((type, address) for (type, address) in
            zip(self.server._streamtypes, addresses) if address)
        self.session.ffmpeg = self.server._ffmpeg(
            self.session.ospath, options, streams, stdout=subprocess.DEVNULL)
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
        self.session.other_addresses(self.stream)):
            raise basehttp.ErrorResponse(ONLY_AGGREGATE_OPERATION_ALLOWED)
        
        if "Range" in self.headers:
            msg = "Deferred pausing not supported"
            raise basehttp.ErrorResponse(HEADER_FIELD_NOT_VALID_FOR_RESOURCE,
                msg)
        
        if self.session.ffmpeg:
            self.session.end()
            self.session.ffmpeg = None
            msg = None
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
    print(server.server_address)
    server.serve_forever()

if __name__ == "__main__":
    try:
        from funcparams import command
        command()
    except (KeyboardInterrupt, BrokenPipeError):
        raise SystemExit(1)
