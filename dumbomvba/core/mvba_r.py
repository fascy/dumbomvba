import json
import traceback
import gevent
from collections import namedtuple
from enum import Enum
from gevent import monkey
from gevent.queue import Queue
from dumbomvba.core.mvba import dumbo_mvba
from dumbomvba.core.acs import mvbacommonsubset

from dumbobft.core.provablereliablebroadcast import provablereliablebroadcast
from dumbobft.core.validatedcommonsubset import validatedcommonsubset
from honeybadgerbft.crypto.threshsig.boldyreva import serialize, deserialize1

from honeybadgerbft.core.honeybadger_block import honeybadger_block
from honeybadgerbft.exceptions import UnknownTagError

monkey.patch_all()


class BroadcastTag(Enum):
    ACS_VACS = 'ACS_VACS'
    TPKE = 'TPKE'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ACS_VACS', 'TPKE'))


def broadcast_receiver(recv_func, recv_queues):
    sender, (tag, j, msg) = recv_func()
    if tag not in BroadcastTag.__members__:
        # TODO Post python 3 port: Add exception chaining.
        # See https://www.python.org/dev/peps/pep-3134/
        raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
            tag, BroadcastTag.__members__.keys()))
    recv_queue = recv_queues._asdict()[tag]

    # if tag == BroadcastTag.ACS_VACS.value:
        # recv_queue = recv_queue[j]
    try:
        recv_queue.put_nowait((sender, msg))
    except AttributeError as e:
        print("error", sender, (tag, j, msg))
        traceback.print_exc(e)


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        broadcast_receiver(recv_func, recv_queues)


class mvba():
    r"""Dumbo object used to run the protocol.

    :param str sid: The base name of the common coin that will be used to
        derive a nonce to uniquely identify the coin.
    :param int pid: Node id.
    :param int B: Batch size of transactions.
    :param int N: Number of nodes in the network.
    :param int f: Number of faulty nodes that can be tolerated.
    :param str sPK: Public key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param str sSK: Signing key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param str sPK1: Public key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param str sSK1: Signing key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param str ePK: Public key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param str eSK: Signing key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param send:
    :param recv:
    :param K: a test parameter to specify break out after K rounds
    """

    def __init__(self, sid, pid, B, N, f, sPK, sSK, sPK1, sSK1, ePK, eSK, send, recv, K=3, logger=None):
        self.sid = sid
        self.id = pid
        self.B = B
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.sPK1 = sPK1
        self.sSK1 = sSK1
        self.ePK = ePK
        self.eSK = eSK
        self._send = send
        self._recv = recv
        self.logger = logger
        self.round = 0  # Current block number
        self.transaction_buffer = []
        self._per_round_recv = {}  # Buffer of incoming messages

        self.K = K

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        """
        print('backlog_tx', self.id, tx)
        if self.logger != None: self.logger.info('Backlogged tx at Node %d:' % self.id + str(tx))
        self.transaction_buffer.append(tx)

    def run(self):
        """Run the Dumbo protocol."""

        def _recv():
            """Receive messages."""
            while True:
                (sender, (r, msg)) = self._recv()

                # Maintain an *unbounded* recv queue for each epoch
                if r not in self._per_round_recv:
                    # Buffer this message
                    assert r >= self.round      # pragma: no cover
                    self._per_round_recv[r] = Queue()

                _recv = self._per_round_recv[r]
                if _recv is not None:
                    # Queue it
                    _recv.put_nowait((sender, msg))

                # else:
                # We have already closed this
                # round and will stop participating!

        self._recv_thread = gevent.spawn(_recv)

        while True:
            # For each round...
            r = self.round
            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            # Select all the transactions (TODO: actual random selection)
            tx_to_send = self.transaction_buffer[:self.B]

            # TODO: Wait a bit if transaction buffer is not full

            # Run the round
            def _make_send(r):
                def _send(j, o):
                    self._send(j, (r, o))
                return _send

            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get
            new_tx = self._run_round(r, tx_to_send, send_r, recv_r)
            # print('new block at %d:' % self.id, new_tx)
            if self.logger != None: self.logger.info('Node %d Delivers Block %d: ' % (self.id, self.round) + str(new_tx))

            # Remove all of the new transactions from the buffer
            self.transaction_buffer = [_tx for _tx in self.transaction_buffer if _tx not in new_tx]
            # print('buffer at %d:' % self.id, self.transaction_buffer)
            if self.logger != None: self.logger.info('Backlog Buffer at Node %d:' % self.id + str(self.transaction_buffer))

            self.round += 1     # Increment the round
            if self.round >= self.K:
                break   # Only run one round for now
        if self.logger != None:
            self.logger.info("node %d breaks" % self.id)
        else:
            print("node %d breaks" % self.id)



    def _run_round(self, r, tx_to_send, send, recv):
        """Run one protocol round.

        :param int r: round id
        :param tx_to_send: Transaction(s) to process.
        :param send:
        :param recv:
        """
        # Unique sid for each round
        print(self.id, "now run the round ", r)
        sid = self.sid + ':' + str(r)
        pid = self.id
        N = self.N
        f = self.f

        vacs_recv = Queue()

        vacs_input = Queue(1)

        vacs_output = Queue(1)


        print(pid, r, 'tx_to_send:', tx_to_send)
        if self.logger != None: self.logger.info('Commit tx at Node %d:' % self.id + str(tx_to_send))

        def _setup_vacs():

            def vacs_send(k, o):
                """Threshold encryption broadcast."""
                send(k, ('ACS_VACS', '', o))

            def vacs_predicate(j, vj):
                try:
                    sid, roothash, raw_Sig = vj
                    digest = self.sPK1.hash_message(str((sid, j, roothash)))
                    assert self.sPK1.verify_signature(deserialize1(raw_Sig), digest)
                    return True
                except AssertionError:
                    print("Failed to verify proof for RBC")
                    return False
            
            mvbaacs = gevent.spawn(mvbacommonsubset, sid+'VACS'+str(r), pid, N, f, self.sPK, self.sSK, self.sPK1, self.sSK1,
                         vacs_input.get, vacs_output.put_nowait,
                         vacs_recv.get, vacs_send)

        _setup_vacs()

                # One instance of TPKE
        def tpke_bcast(o):
            """Threshold encryption broadcast."""
            def broadcast(o):
                """Multicast the given input ``o``.

                :param o: Input to multicast.
                """
                for j in range(N):
                    send(j, o)
            broadcast(('TPKE', 0, o))

        tpke_recv = Queue()

        recv_queues = BroadcastReceiverQueues(
            ACS_VACS=vacs_recv,
            TPKE=tpke_recv
        )
        gevent.spawn(broadcast_receiver_loop, recv, recv_queues)

        _input = Queue(1)
        _input.put(json.dumps(tx_to_send))

        _output = honeybadger_block(pid, self.N, self.f, self.ePK, self.eSK,
                          _input.get,
                          acs_in=vacs_input.put_nowait, acs_out=vacs_output.get,
                          tpke_bcast=tpke_bcast, tpke_recv=tpke_recv.get)

        block = set()
        for batch in _output:
            decoded_batch = json.loads(batch.decode())
            print("here is the batch:", decoded_batch, pid)
            for tx in decoded_batch:
                block.add(tx)
        
        print (list(block))

        return list(block)

    # TODO： make help and callhelp threads to handle the rare cases when vacs (vaba) returns None
