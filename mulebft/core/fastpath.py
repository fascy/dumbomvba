from collections import defaultdict

import gevent, time
from gevent.event import Event
from gevent.queue import Queue

from honeybadgerbft.crypto.threshsig.boldyreva import serialize, deserialize1
from honeybadgerbft.crypto.ecdsa.ecdsa import ecdsa_sign, ecdsa_vrfy
import json
from gevent import Timeout
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def fastpath(sid, pid, N, f, get_input, put_output, S, B, T, h_genesis, PK1, SK1, PK2s, SK2, recv, send):
    """Fast path, Byzantine Safe Broadcast
    :param str sid: ``the string of identifier``
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param get_input: a function to get input TXs, e.g., input() to get a transaction
    :param put_output: a function to deliver output blocks, e.g., output(block)
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold N-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold N-f
    :param PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param T: timeout of a slot
    :param S: number of slots in a epoch
    :param B: batch size, i.e., the number of TXs in a batch
    :param recv: function to receive incoming messages
    :param send: function to send outgoing messages
    """

    TIMEOUT = T
    SLOTS_NUM = S
    BATCH_SIZE = B

    try:
        leader = int(sid[-1:])
    except:
        leader = 0

    print("leader is node " + str(leader))

    slot_cur = 1

    h_prev = h_genesis
    pending_block = None
    notraized_block = None

    # Leader's temp variables
    voters = defaultdict(lambda: set())
    votes = defaultdict(lambda: dict())
    batches = defaultdict(lambda: dict())
    decides = defaultdict(lambda: Queue(1))

    is_noncritical_signal = Event()
    is_noncritical_signal.set()

    def bcast(m):
        for i in range(N):
            send(i, m)

    def handle_messages():
        nonlocal leader, h_prev, pending_block, notraized_block, batches, voters, votes, slot_cur
        while True:
            (sender, msg) = recv()
            assert sender in range(N)

            # Enter critical block
            is_noncritical_signal.clear()

            if msg[0] == 'VOTE':
                if pid != leader:
                    continue
                else:
                    _, slot, h_p, sig_p, tx_batch, sig = msg

                    try:
                        assert PK1.verify_share(sig_p, sender, PK1.hash_message(str((h_p, slot-1))))
                    except AssertionError:
                        print("Signature failed!")
                        continue

                    try:
                        assert ecdsa_vrfy(PK2s[sender], tx_batch, sig)
                    except AssertionError:
                        print("Signature failed!")
                        continue

                    if sender not in voters[slot]:
                        voters[slot].add(sender)
                        votes[slot][sender] = sig_p
                        batches[slot][sender] = (tx_batch, sig)

                    if len(voters[slot_cur]) == N - f:
                        Simga = PK1.combine_shares(votes[slot_cur])
                        signed_batches = tuple(batches[slot_cur].items())
                        bcast(('DECIDE', slot_cur, h_prev, Simga, signed_batches))

            if msg[0] == "DECIDE":
                _, slot, h_p, Sig, signed_batches = msg

                try:
                    digest = PK1.hash_message(str((h_p, slot-1)))
                    assert PK1.verify_signature(Sig, digest)
                except AssertionError:
                    print("Notarization signature failed!")
                    continue
                try:
                    assert len(signed_batches) >= N - f
                except AssertionError:
                    print("Not enough batches!")

                for item in signed_batches:
                    proposer, (tx_batch, sig) = item
                    try:
                        ecdsa_vrfy(PK2s[proposer], tx_batch, sig)
                    except AssertionError:
                        print("Batch signatures failed!")
                        continue

                decides[slot].put((h_p, Sig, signed_batches))

            is_noncritical_signal.set()
            # Leave critical block

    def one_slot():
        nonlocal pending_block, notraized_block, h_prev, slot_cur

        digest = PK1.hash_message(str((h_prev, slot_cur-1)))
        sig_prev = SK1.sign(digest)
        if slot_cur == SLOTS_NUM + 1 or slot_cur == SLOTS_NUM + 2:
            tx_batch = 'Dummy'
        else:
            tx_batch = json.dumps([get_input() for _ in range(BATCH_SIZE)])
        sig_tx = ecdsa_sign(SK2, tx_batch)

        send(leader, ('VOTE', slot_cur, h_prev, sig_prev, tx_batch, sig_tx))

        (h_p, sig, signed_batches) = decides[slot_cur].get()  # Block to wait for the voted block

        if pending_block is not None:
            notraized_block = (pending_block[0], pending_block[1], pending_block[2], pending_block[4])
            print(notraized_block)
            put_output(notraized_block)

        pending_block = (sid, slot_cur, h_prev, sig, signed_batches)
        h_prev = hash((sid, slot_cur, h_prev, signed_batches))

    recv_thread = gevent.spawn(handle_messages)

    while slot_cur <= SLOTS_NUM + 2:
        print("node " + str(pid) + " starts the slot " + str(slot_cur) + " ...")
        print(is_noncritical_signal.is_set())

        timeout = Timeout(TIMEOUT, False)
        timeout.start()

        with Timeout(TIMEOUT):
            try:
                slot_thread = gevent.spawn(one_slot)
                slot_thread.join()
                print("node " + str(pid) + " finishes the slot " + str(slot_cur) + " ...")
                slot_cur = slot_cur + 1
            except Timeout:
                pass
            finally:
                timeout.cancel()
                try:
                    is_noncritical_signal.wait()
                    gevent.killall([slot_thread])
                except Timeout as e:
                    print("error: " + str(e))
                    break
