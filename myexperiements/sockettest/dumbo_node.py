import random
import gevent
import os
import pickle

from gevent import time
from dumbobft.core.dumbo import Dumbo
from myexperiements.sockettest.make_random_tx import tx_generator
from myexperiements.sockettest.socket_server import Node, set_logger_of_node


def load_key(id):

    with open(os.getcwd() + '/keys/' + 'sPK.key', 'rb') as fp:
        sPK = pickle.load(fp)

    with open(os.getcwd() + '/keys/' + 'sPK1.key', 'rb') as fp:
        sPK1 = pickle.load(fp)

    with open(os.getcwd() + '/keys/' + 'ePK.key', 'rb') as fp:
        ePK = pickle.load(fp)

    with open(os.getcwd() + '/keys/' + 'sSK-' + str(id) + '.key', 'rb') as fp:
        sSK = pickle.load(fp)

    with open(os.getcwd() + '/keys/' + 'sSK1-' + str(id) + '.key', 'rb') as fp:
        sSK1 = pickle.load(fp)

    with open(os.getcwd() + '/keys/' + 'eSK-' + str(id) + '.key', 'rb') as fp:
        eSK = pickle.load(fp)

    return sPK, sPK1, ePK, sSK, sSK1, eSK


class DumboBFTNode (Dumbo):

    def __init__(self, sid, id, B, N, f, addresses_list: list, K=3, mode='debug', tx_buffer=None):
        self.sPK, self.sPK1, self.ePK, self.sSK, self.sSK1, self.eSK = load_key(id)
        Dumbo.__init__(self, sid, id, B, N, f, self.sPK, self.sSK, self.sPK1, self.sSK1, self.ePK, self.eSK, send=None, recv=None, K=K, logger=set_logger_of_node(id))
        self.server = Node(id=id, ip=addresses_list[id][0], port=addresses_list[id][1], addresses_list=addresses_list, logger=self.logger)
        self.mode = mode
        self._prepare_bootstrap()

    def _prepare_bootstrap(self):
        if self.mode == 'test' or 'debug':
            for r in range(self.K * self.B):
                tx = tx_generator(250) # Set each dummy TX to be 250 Byte
                Dumbo.submit_tx(self, tx)
        else:
            pass
            # TODO: submit transactions through tx_buffer

    def start_socket_server(self):
        pid = os.getpid()
        #print('pid: ', pid)
        self.logger.info('node id %d is running on pid %d' % (self.id, pid))
        self.server.start()

    def connect_socket_servers(self):
        self.server.connect_all()
        self._send = self.server.send
        self._recv = self.server.recv

    def run_hbbft_instance(self):
        self.start_socket_server()
        time.sleep(3)
        gevent.sleep(3)
        self.connect_socket_servers()
        time.sleep(3)
        gevent.sleep(3)
        self.run()


def main(sid, i, B, N, f, addresses, K):
    badger = DumboBFTNode(sid, i, B, N, f, addresses, K)
    badger.run_hbbft_instance()


if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sid', metavar='sid', required=True,
                        help='identifier of node', type=str)
    parser.add_argument('--id', metavar='id', required=True,
                        help='identifier of node', type=int)
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    parser.add_argument('--B', metavar='B', required=True,
                        help='size of batch', type=int)
    parser.add_argument('--K', metavar='K', required=True,
                        help='rounds to execute', type=int)
    args = parser.parse_args()

    # Some parameters
    sid = args.sid
    i = args.id
    N = args.N
    f = args.f
    B = args.B
    K = args.K

    # Random generator
    rnd = random.Random(sid)

    # Nodes list
    host = "127.0.0.1"
    port_base = int(rnd.random() * 5 + 1) * 10000
    addresses = [(host, port_base + 200 * i) for i in range(N)]
    print(addresses)

    main(sid, i, B, N, f, addresses, K)
