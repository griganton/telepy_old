import threading, queue
item = queue.Queue()
def consume():
    """Потребление очередного элемента (с ожиданием его появления)"""
    return item.get()

def consumer():
    while True:
        print(consume())

def produce(i):
    """Занесение нового элемента в контейнер и оповещение потоков"""
    item.put(i)

p1 = threading.Thread(target=consumer, name="t1")
p1.setDaemon(True)
p2 = threading.Thread(target=consumer, name="t2")
p2.setDaemon(True)
p1.start()
p2.start()
produce("ITEM1")
produce("ITEM2")
produce("ITEM3")
produce("ITEM4")
p1.join()
p2.join()
