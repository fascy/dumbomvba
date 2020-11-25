import gevent
from gevent import monkey
from gevent.event import Event
from collections import defaultdict
import logging

from honeybadgerbft.exceptions import RedundantMessageError, AbandonedNodeError
monkey.patch_all()

logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)
#ch = logging.StreamHandler(sys.stdout)
#ch.setFormatter(format)
#logger.addHandler(ch)


def twovalueagreement(sid, pid, N, f, coin, input, decide, receive, send):
    """Binary consensus from [MMR14]. It takes an input ``vi`` and will
    finally write the decided value into ``decide`` channel.

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param coin: a ``common coin(r)`` is called to block until receiving a bit
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide(0)`` or ``output(1)`` is eventually called
    :param send: send channel
    :param receive: receive channel
    :return: blocks until
    """
    # Messages received are routed to either a shared coin, the broadcast, or AUX
    est_values = defaultdict(lambda: defaultdict(lambda: set()))
    aux_values = defaultdict(lambda: defaultdict(lambda: set()))
    conf_values = defaultdict(lambda: defaultdict(lambda: set()))
    est_sent = defaultdict(lambda: defaultdict(lambda: False))
    conf_sent = defaultdict(lambda: defaultdict(lambda: False))
    int_values = defaultdict(set)

    # This event is triggered whenever int_values or aux_values changes
    bv_signal = Event()

    def broadcast(o):
        for i in range(N):
            send(i, o)

    def _recv():
        while True:  # not finished[pid]:
            (sender, msg) = receive()
            logger.debug(f'receive {msg} from node {sender}',
                         extra={'nodeid': pid, 'epoch': msg[1]})
            assert sender in range(N)

            if msg[0] == 'EST':
                # BV_Broadcast message
                _, r, v = msg
                assert type(v) is int
                if sender in est_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    # print(f'Redundant EST received by {sender}', msg)
                    logger.warning(
                        f'Redundant EST message received by {sender}: {msg}',
                        extra={'nodeid': pid, 'epoch': msg[1]}
                    )
                    # raise RedundantMessageError(
                    #    'Redundant EST received {}'.format(msg))
                    continue

                est_values[r][v].add(sender)
                # Relay after reaching first threshold
                if len(est_values[r][v]) >= f + 1 and not est_sent[r][v]:
                    est_sent[r][v] = True
                    broadcast(('EST', r, v))
                    logger.debug(f"broadcast {('EST', r, v)}",
                                 extra={'nodeid': pid, 'epoch': r})

                # Output after reaching second threshold
                if len(est_values[r][v]) >= 2 * f + 1:
                    logger.debug(
                        f'add v = {v} to bin_value[{r}] = {int_values[r]}',
                        extra={'nodeid': pid, 'epoch': r},
                    )
                    int_values[r].add(v)
                    logger.debug(f'bin_values[{r}] is now: {int_values[r]}',
                                 extra={'nodeid': pid, 'epoch': r})
                    bv_signal.set()

            elif msg[0] == 'AUX':
                # Aux message
                _, r, v = msg
                assert type(v) is int
                if sender in aux_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    print('Redundant AUX received', msg)
                    raise RedundantMessageError(
                        'Redundant AUX received {}'.format(msg))

                logger.debug(
                    f'add sender = {sender} to aux_value[{r}][{v}] = {aux_values[r][v]}',
                    extra={'nodeid': pid, 'epoch': r},
                )
                aux_values[r][v].add(sender)
                logger.debug(
                    f'aux_value[{r}][{v}] is now: {aux_values[r][v]}',
                    extra={'nodeid': pid, 'epoch': r},
                )
                bv_signal.set()

            elif msg[0] == 'CONF':
                _, r, v = msg
                assert len(v) == 1 or len(v) == 2
                if sender in conf_values[r][v]:
                    logger.warning(f'Redundant CONF received {msg} by {sender}',
                                   extra={'nodeid': pid, 'epoch': r})
                    # FIXME: Raise for now to simplify things & be consistent
                    # with how other TAGs are handled. Will replace the raise
                    # with a continue statement as part of
                    # https://github.com/initc3/HoneyBadgerBFT-Python/issues/10
                    raise RedundantMessageError(
                        'Redundant CONF received {}'.format(msg))
                conf_values[r][v].add(sender)
                logger.debug(
                    f'add v = {v} to conf_value[{r}] = {conf_values[r]}',
                    extra={'nodeid': pid, 'epoch': r},
                )
                bv_signal.set()

    # Translate mmr14 broadcast into coin.broadcast
    # _coin_broadcast = lambda (r, sig): broadcast(('COIN', r, sig))
    # _coin_recv = Queue()
    # coin = shared_coin(sid+'COIN', pid, N, f, _coin_broadcast, _coin_recv.get)

    # Run the receive loop in the background
    _thread_recv = gevent.spawn(_recv)

    # Block waiting for the input
    # print(pid, sid, 'PRE-ENTERING CRITICAL')
    vi = input()
    # print(pid, sid, 'PRE-EXITING CRITICAL', vi)

    assert type(vi) is int
    est = vi
    r = 0
    already_decided = None
    while True:  # Unbounded number of rounds
        # print("debug", pid, sid, 'deciding', already_decided, "at epoch", r)

        logger.info(f'Starting with est = {est}',
                    extra={'nodeid': pid, 'epoch': r})

        if not est_sent[r][est]:
            est_sent[r][est] = True
            broadcast(('EST', r, est))

        # print("debug", pid, sid, 'WAITS BIN VAL at epoch', r)

        while len(int_values[r]) == 0:
            # Block until a value is output
            bv_signal.clear()
            bv_signal.wait()

        # print("debug", pid, sid, 'GETS BIN VAL at epoch', r)

        w = next(iter(int_values[r]))  # take an element
        logger.debug(f"broadcast {('AUX', r, w)}",
                     extra={'nodeid': pid, 'epoch': r})
        broadcast(('AUX', r, w))

        logger.debug(
            f'block until at least N-f ({N-f}) AUX values are received',
            extra={'nodeid': pid, 'epoch': r})

        while True:
            logger.debug(f'int_values[{r}]: {int_values[r]}',
                         extra={'nodeid': pid, 'epoch': r})
            logger.debug(f'aux_values[{r}]: {aux_values[r]}',
                         extra={'nodeid': pid, 'epoch': r})
            len_int_values = len(int_values[r])
            assert len_int_values == 1 or len_int_values == 2
            if len_int_values == 1:
                if len(aux_values[r][tuple(int_values[r])[0]]) >= N - f:
                    values = set(int_values[r])
                    break
            else:
                if sum(len(aux_values[r][v]) for v in int_values[r]) >= N - f:
                    values = set(int_values[r])
                    break
            bv_signal.clear()
            bv_signal.wait()

        logger.debug(f'Completed AUX phase with values = {values}',
                     extra={'nodeid': pid, 'epoch': r})

        # CONF phase
        logger.debug(
            f'block until at least N-f ({N-f}) CONF values are received',
            extra={'nodeid': pid, 'epoch': r})

        if not conf_sent[r][tuple(values)]:
            logger.debug(f"broadcast {('CONF', r, tuple(values))}",
                     extra={'nodeid': pid, 'epoch': r})
            broadcast(('CONF', r, tuple(int_values[r])))
            conf_sent[r][tuple(values)] = True
        while True:
            logger.debug(
                f'looping ... conf_values[epoch] is: {conf_values[r]}',
                extra={'nodeid': pid, 'epoch': r},
            )
            # len_int_values = len(int_values[r])
            # assert len_int_values == 1 or len_int_values == 2
            if len(conf_values[r][tuple(int_values[r])]) >= N - f:
                values = set(int_values[r])
                break
            bv_signal.clear()
            bv_signal.wait()

        logger.debug(f'Completed CONF phase with values = {values}',
                     extra={'nodeid': pid, 'epoch': r})

        logger.debug(
            f'Block until receiving the common coin value',
            extra={'nodeid': pid, 'epoch': r},
        )
        # Block until receiving the common coin value

        # print("debug", pid, sid, 'fetchs a coin at epoch', r)
        s = coin(r)
        # print("debug", pid, sid, 'gets a coin', s, 'at epoch', r)

        logger.info(f'Received coin with value = {s}',
                    extra={'nodeid': pid, 'epoch': r})

        try:
            est, already_decided = set_new_estimate(
                values=values,
                s=s,
                already_decided=already_decided,
                decide=decide,
            )
            # print('debug then decided:', already_decided, '%s' % sid)
        except AbandonedNodeError:
            # print('debug node %d quits %s' % (pid, sid))
            # print('[sid:%s] [pid:%d] QUITTING in round %d' % (sid,pid,r)))
            logger.debug(f'QUIT!',
                         extra={'nodeid': pid, 'epoch': r})
            _thread_recv.kill()
            return

        r += 1


def set_new_estimate(*, values, s, already_decided, decide):
    if len(values) == 1:
        v = next(iter(values))
        assert type(v) is int
        if (v % 2) == s:
            if already_decided is None:
                already_decided = v
                decide(v)
            elif already_decided == v:
                # Here corresponds to a proof that if one party
                # decides at round r, then in all the following
                # rounds, everybody will propose r as an
                # estimation. (Lemma 2, Lemma 1) An abandoned
                # party is a party who has decided but no enough
                # peers to help him end the loop.  Lemma: # of
                # abandoned party <= t
                raise AbandonedNodeError
        est = v
    else:
        vals = tuple(values)
        assert len(values) == 2
        assert type(vals[0]) is int
        assert type(vals[1]) is int
        assert abs(vals[0] - vals[1]) == 1
        if vals[0] % 2 == s:
            est = vals[0]
        else:
            est = vals[1]
    return est, already_decided
