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
        WaitingProcess(self.downstream_queue, self.__on_downstream_message__wrapper).start()
        if underlying_layer is not None:
            WaitingProcess(self.underlying_layer.upstream_queue, self.__on_upstream_message_wrapper).start()
        # starting thread
        threading.Thread(target=self.run).start()

    def __on_downstream_message__wrapper(self, message):
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
        """Override me. Provides dummy functionality on default."""
        self.upstream_queue.put(message)

    def to_lower(self, message):
        """Override me. Provides dummy functionality on default."""
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
            except AttributeError:
                # Queue does not exist
                # Stop waiting
                return


class LayerWithSubscribe(Layer):
    def __init__(self, *args, **kwargs):
        Layer.__init__(self, *args, **kwargs)
        self.__subscribe_dict = {}
        # start

    def __on_upstream_message_wrapper(self, message):
        print(message.name)
        if message.name in self.__subscribe_dict.keys():
            self.__subscribe_dict[message.type](message)
        else:
            self.on_upstream_message(message)

    def subscribe(self, result_name, func):
        """Putting functions to subscribe list"""
        self.__subscribe_dict[result_name] = func