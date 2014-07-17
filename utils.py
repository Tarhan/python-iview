import net
import selectors
from socketserver import StreamRequestHandler

class SelectableServer(net.Server):
    def __init__(self, *pos, **kw):
        super().__init__(*pos, **kw)
        self.selector = None
        self.selected = False
        self.handlers = set()
    
    def register(self, selector):
        self.selector = selector
        self.selector.register(self.fileno(), selectors.EVENT_READ, self)
    
    def handle_select(self):
        self.selected = True
        self.handle_request()
        self.selected = False
    
    def process_request(self, *pos, **kw):
        if not self.selected:
            return super().process_request(*pos, **kw)
        self.finish_request(*pos, **kw)
    
    def close(self):
        while self.handlers:
            next(iter(self.handlers)).close()
        if self.selector:
            self.selector.unregister(self.fileno())
        return super().close()

class SelectableHandler(BaseRequestHandler):
    def handle(self):
        if not self.server.selected:
            return super().handle()
        self.server.selector.register(self.rfile, selectors.EVENT_READ, self)
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
