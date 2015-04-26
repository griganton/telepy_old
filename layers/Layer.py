__author__ = 'agrigoryev'
import queue
import threading

class Layer:
    def __init__(self, name="Unnamed",  underlying_layer=None):
        """Override the on_upstream_message(self, message)"""
        assert isinstance(underlying_layer, Layer) or underlying_layer is None
        self.underlying_layer = underlying_layer
        self.name = name
        self.upstream_queue = queue.Queue()
        self.downstream_queue = queue.Queue()
        # start
        WaitingProcess(self.downstream_queue, self.__on_downstream_message_wrapper).start()
        if underlying_layer is not None:
            WaitingProcess(self.underlying_layer.upstream_queue, self.__on_upstream_message_wrapper).start()
        # starting thread
        threading.Thread(target=self.run).start()

    def __on_downstream_message_wrapper(self, message):
        self.on_downstream_message(message)

    def __on_upstream_message_wrapper(self, message):
        self.on_upstream_message(message)

    def on_upstream_message(self, message):
        """Override me. Provides dummy functionality on default."""
        self.to_upper(message)

    def on_downstream_message(self, message):
        """Override me. Provides dummy functionality on default."""
        self.to_lower(message)

    def to_upper(self, message):
        self.upstream_queue.put(message)

    def to_lower(self, message):
        self.underlying_layer.downstream_queue.put(message)

    def run(self):
        """Override me. Provides dummy functionality on default."""
        pass


class WaitingProcess(threading.Thread):
    """Creates thread that waits message from the queue and then running the defined function"""
    def __init__(self, queue_to_wait, callback_func):
        threading.Thread.__init__(self)
        self.func = callback_func
        self.queue = queue_to_wait
        self.daemon = True

    def run(self):
        """Infinitely waiting for message from the queue.
           If queue is deleted, stops waiting and finishes thread."""
        while True:
            try:
                message = self.queue.get()
                self.func(message)
            except queue.Empty:
                # nothing in the queue. Do nothing
                pass
