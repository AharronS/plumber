import SocketServer, time, select, sys
from threading import Thread

COMMAND_HELLO = 1
COMMAND_QUIT  = 2

# The SimpleRequestHandler class uses this to parse command lines.
class SimpleCommandProcessor:
    def __init__(self):
        pass

    def process(self, line, request):
        """Process a command"""
        args = line.split(' ')
        command = args[0].lower()
        args = args[1:]

        if command == 'hello':
            request.send('HELLO TO YOU TO!\n\r')
            return COMMAND_HELLO
        elif command == 'quit':
            request.send('OK, SEE YOU LATER\n\r')
            return COMMAND_QUIT
        else:
            request.send('Unknown command: "%s"\n\r' % command)


# SimpleServer extends the TCPServer, using the threading mix in
# to create a new thread for every request.
class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):

    # This means the main server will not do the equivalent of a
    # pthread_join() on the new threads.  With this set, Ctrl-C will
    # kill the server reliably.
    daemon_threads = True

    # By setting this we allow the server to re-bind to the address by
    # setting SO_REUSEADDR, meaning you don't have to wait for
    # timeouts when you kill the server and the sockets don't get
    # closed down correctly.
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, processor, message=''):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.processor = processor
        self.message = message

# The RequestHandler handles an incoming request.  We have extended in
# the SimpleServer class to have a 'processor' argument which we can
# access via the passed in server argument, but we could have stuffed
# all the processing in here too.
class SimpleRequestHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.request.send(self.server.message)

        ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], None)

        text = ''
        done = False
        while not done:

            if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
                data = self.request.recv(1024)

                if not data:
                    break
                elif len(data) > 0:
                    text += str(data)

                    while text.find("\n") != -1:
                        line, text = text.split("\n", 1)
                        line = line.rstrip()

                        command = self.server.processor.process(line,
                                                                self.request)

                        if command == COMMAND_HELLO:
                            break
                        elif command == COMMAND_QUIT:
                            done = True
                            break

        self.request.close()

    def finish(self):
       """Nothing"""

def runSimpleServer():
    # Start up a server on localhost, port 7000; each time a new
    # request comes in it will be handled by a SimpleRequestHandler
    # class; we pass in a SimpleCommandProcessor class that will be
    # able to be accessed in request handlers via server.processor;
    # and a hello message.
    server = SimpleServer(('', 7000), SimpleRequestHandler,
                          SimpleCommandProcessor(), 'Welcome to the SimpleServer.\n\r')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    runSimpleServer()