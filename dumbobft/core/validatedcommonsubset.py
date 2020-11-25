import traceback
import gevent
from collections import namedtuple
from enum import Enum
from gevent import monkey
from dumbobft.core.validatedagreement import validatedagreement
from gevent.queue import Queue
from honeybadgerbft.exceptions import UnknownTagError

monkey.patch_all()


class MessageTag(Enum):
    VACS_VAL = 'VACS_VAL'            # Queue()
    VACS_VABA = 'VACS_VABA'          # Queue()


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('VACS_VAL', 'VACS_VABA'))


def handle_vacs_messages(recv_func, recv_queues):
    sender, (tag, msg) = recv_func()
    # print(sender, (tag, msg))
    if tag not in MessageTag.__members__:
        # TODO Post python 3 port: Add exception chaining.
        # See https://www.python.org/dev/peps/pep-3134/
        raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
            tag, MessageTag.__members__.keys()))
    recv_queue = recv_queues._asdict()[tag]
    try:
        recv_queue.put_nowait((sender, msg))
    except AttributeError as e:
        # print((sender, msg))
        traceback.print_exc(e)


def vacs_msg_receiving_loop(recv_func, recv_queues):
    while True:
        handle_vacs_messages(recv_func, recv_queues)


def validatedcommonsubset(sid, pid, N, f, PK, SK, PK1, SK1, input, decide, receive, send, predicate=lambda i, v: True):
    """Validated vector consensus. It takes an input ``vi`` and will
    finally writes the decided value (i.e., a vector of different nodes' vi) into ``decide`` channel.
    Each vi is validated by a predicate function predicate(i, vi)

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param PK: ``boldyreva.TBLSPublicKey`` with threshold f+1
    :param SK: ``boldyreva.TBLSPrivateKey`` with threshold f+1
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate(i, v)`` represents the externally validated condition where i represent proposer's pid
    """

    assert PK.k == f + 1
    assert PK.l == N
    assert PK1.k == N - f
    assert PK1.l == N

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    valueSenders = set()  # Peers that have sent us valid VAL messages

    vaba_input = Queue(1)
    vaba_recv = Queue()
    vaba_output = Queue(1)

    value_recv = Queue()

    recv_queues = MessageReceiverQueues(
        VACS_VAL=value_recv,
        VACS_VABA=vaba_recv,
    )
    gevent.spawn(vacs_msg_receiving_loop, receive, recv_queues)

    def make_vaba_send():  # this make will automatically deep copy the enclosed send func
        def vaba_send(k, o):
            """VACS-VABA send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            send(k, ('VACS_VABA', o))

        return vaba_send

    def make_vaba_predicate():
        def vaba_predicate(m):
            counter = 0
            if type(m) is tuple:
                if len(m) == N:
                    for i in range(N):
                        if m[i] is not None and predicate(i, m[i]):
                            counter += 1
            return True if counter >= N - f else False

        return vaba_predicate

    vaba = gevent.spawn(validatedagreement, sid + 'VACS-VABA', pid, N, f, PK, SK, PK1, SK1,
                        vaba_input.get, vaba_output.put_nowait, vaba_recv.get, make_vaba_send(), make_vaba_predicate())

    """ 
    """
    """ 
    Execution
    """
    """ 
    """

    v = input()
    assert predicate(pid, v)

    for k in range(N):
        send(k, ('VACS_VAL', v))

    values = [None] * N
    while True:
        j, vj = value_recv.get()
        if predicate(j, vj):
            valueSenders.add(j)
            values[j] = vj
            if len(valueSenders) >= N - f:
                break
    print(tuple(values), pid)
    vaba_input.put(tuple(values))
    decide(list(vaba_output.get()))
    vaba.kill()
