import logging

from honeybadgerbft.crypto.threshsig.boldyreva import serialize, deserialize1


from collections import defaultdict
from gevent import Greenlet, monkey
from gevent.queue import Queue
import hashlib
monkey.patch_all()

logger = logging.getLogger(__name__)


class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""
    pass


def hash(x):
    return hashlib.sha256(x).digest()


def shared_coin(sid, pid, N, f, PK, SK, broadcast, receive, single_bit=True):
    """A shared coin based on threshold signatures

    :param sid: a unique instance id
    :param pid: my id number
    :param N: number of parties
    :param f: fault tolerance, :math:`f+1` shares needed to get the coin
    :param PK: ``boldyreva.TBLSPublicKey``
    :param SK: ``boldyreva.TBLSPrivateKey``
    :param broadcast: broadcast channel
    :param receive: receive channel
    :param single_bit: is the output coin a single bit or not ?
    :return: a function ``getCoin()``, where ``getCoin(r)`` blocks
    """
    assert PK.k == f+1
    assert PK.l == N    # noqa: E741
    received = defaultdict(dict)
    outputQueue = defaultdict(lambda: Queue(1))

    def _recv():
        while True:     # main receive loop
            logger.debug(f'entering loop',
                         extra={'nodeid': pid, 'epoch': '?'})
            # New shares for some round r, from sender i
            (i, (_, r, raw_sig)) = receive()
            sig = deserialize1(raw_sig)
            logger.debug(f'received i, _, r, sig: {i, _, r, sig}',
                         extra={'nodeid': pid, 'epoch': r})
            assert i in range(N)
            # assert r >= 0  ### Comment this line since round r can be a string
            if i in received[r]:
                print("redundant coin sig received", (sid, pid, i, r))
                continue

            h = PK.hash_message(str((sid, r)))

            # TODO: Accountability: Optimistically skip verifying
            # each share, knowing evidence available later
            try:
                PK.verify_share(sig, i, h)
            except AssertionError:
                print("Signature share failed!", (sid, pid, i, r))
                continue

            received[r][i] = sig

            # After reaching the threshold, compute the output and
            # make it available locally
            logger.debug(
                f'if len(received[r]) == f + 1: {len(received[r]) == f + 1}',
                extra={'nodeid': pid, 'epoch': r},
            )
            if len(received[r]) == f + 1:

                # Verify and get the combined signature
                sigs = dict(list(received[r].items())[:f+1])
                sig = PK.combine_shares(sigs)
                assert PK.verify_signature(sig, h)

                # Compute the bit from the least bit of the hash
                coin = hash(serialize(sig))[0]
                if single_bit:
                    bit = coin % 2
                    logger.debug(f'put coin {bit} in output queue',
                             extra={'nodeid': pid, 'epoch': r})
                    outputQueue[r].put_nowait(bit)
                else:
                    logger.debug(f'put coin {coin} in output queue',
                             extra={'nodeid': pid, 'epoch': r})
                    outputQueue[r].put_nowait(coin)

    # greenletPacker(Greenlet(_recv), 'shared_coin', (pid, N, f, broadcast, receive)).start()
    Greenlet(_recv).start()

    def getCoin(round):
        """Gets a coin.

        :param round: the epoch/round.
        :returns: a coin.

        """
        # I have to do mapping to 1..l
        h = PK.hash_message(str((sid, round)))
        # print('debug', SK.sign(h))
        # print('debug', type(SK.sign(h)))
        logger.debug(f"broadcast {('COIN', round, SK.sign(h))}",
                     extra={'nodeid': pid, 'epoch': round})
        #sig = SK.sign(h)
        broadcast(('COIN', round, serialize(SK.sign(h))))
        coin = outputQueue[round].get()
        # print('debug', 'node %d gets a coin %d for round %d in %s' % (pid, coin, round, sid))
        return coin

    return getCoin
