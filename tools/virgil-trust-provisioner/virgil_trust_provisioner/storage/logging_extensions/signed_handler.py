from logging import FileHandler, StreamHandler


class SignedHandler(FileHandler):

    def __init__(self, *args, **kwargs):
        super(SignedHandler, self).__init__(*args, **kwargs)
        self.__atmel = kwargs.pop("atmel")

    def _open(self):
        return open(self.baseFilename, self.mode, encoding=self.encoding)

    def close(self):
        self.acquire()
        try:
            try:
                if self.stream:
                    try:
                        self.flush()
                    finally:
                        stream = self.stream
                        self.stream = None
                        if hasattr(stream, "close"):
                            stream.close()
            finally:
                StreamHandler.close(self)
        finally:
            self.release()
        log_file = open(self.baseFilename, "rb")
        log_bytes = log_file.read()


