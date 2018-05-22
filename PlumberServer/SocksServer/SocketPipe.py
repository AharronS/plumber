import thread


class SocketPipe(object):
    BUFFER_SIZE = 1024 * 1024

    def __init__(self, socket1, socket2):
        self._socket1 = socket1
        self._socket2 = socket2
        self.__running = False

    def __transfer(self, socket1, socket2):
        while self.__running:
            try:
                data = socket1.recv(self.BUFFER_SIZE)
                if len(data) > 0:
                    socket2.sendall(data)
                else:
                    break
            except IOError:
                self.stop()
        self.stop()

    def start(self):
        self.__running = True
        thread.start_new_thread(self.__transfer, (self._socket1, self._socket2))
        thread.start_new_thread(self.__transfer, (self._socket2, self._socket1))

    def stop(self):
        self._socket1.close()
        self._socket2.close()
        self.__running = False

    def is_running(self):
        return self.__running

