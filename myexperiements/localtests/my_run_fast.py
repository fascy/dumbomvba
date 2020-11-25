import hashlib
import pickle
import random

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from honeybadgerbft.crypto.threshsig.boldyreva import dealer
from honeybadgerbft.crypto.ecdsa.ecdsa import pki
from mulebft.core.fastpath import fastpath


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def simple_router(N, maxdelay=0.1, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)

    queues = [Queue() for _ in range(N)]

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            print(('SEND %8s [%2d -> %2d]' % (o[0], i, j)) + str(o))
            gevent.spawn_later(delay, queues[j].put, (i, o))
            #queues[j].put((i, o))
        return _send

    def makeRecv(j):
        def _recv():
            (i, o) = queues[j].get()
            print(('RECV %8s [%2d -> %2d]' % (o[0], i, j)) + str(o))
            return (i, o)
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])


def _test_fast(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    sid = 'sidA1'
    BATCH_SIZE = 2
    SLOTS_NUM = 100
    TIMEOUT = 0.35
    GENESIS = hash('GENESIS')

    # Note thld siganture for CBC has a threshold different from common coin's
    PK1, SK1s = dealer(N, N - f)
    PK2s, SK2s = pki(N)

    inputs = [Queue() for _ in range(N)]
    outputs = [Queue() for _ in range(N)]

    for i in range(N):
        for j in range(BATCH_SIZE * SLOTS_NUM):
            inputs[i].put("<TX " + str(j) + " from node " + str(i) + ">")

    sends, recvs = simple_router(N, seed=seed)

    threads = []

    for i in range(N-1):

        t = Greenlet(fastpath, sid, i, N, f,
                     inputs[i].get, outputs[i].put_nowait, SLOTS_NUM, BATCH_SIZE, TIMEOUT, GENESIS,
                     PK1, SK1s[i], PK2s, SK2s[i], recvs[i], sends[i])

        t.start()
        threads.append(t)

    gevent.joinall(threads)


def test_fast(N, f, seed):
    _test_fast(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_fast(4, 1, None)
