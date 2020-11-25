import random
import traceback

from myexperiements.sockettest.hbbft_node import HoneyBadgerBFTNode
from myexperiements.sockettest.dumbo_node import DumboBFTNode


def instantiate_hbbft_node(sid, i, B, N, f, addresses, K):
    dumbo = DumboBFTNode(sid, i, B, N, f, addresses, K)
    dumbo.run_hbbft_instance()
    #badger = HoneyBadgerBFTNode(sid, i, B, N, f, addresses, K)
    #badger.run_hbbft_instance()


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
    addresses = [None] * N
    try:
        with open('hosts.config', 'r') as hosts:
            for line in hosts:
                params = line.split()
                pid = int(params[0])
                ip = params[1]
                port = int(params[2])
                # print(pid, ip, port)
                if pid not in range(N):
                    continue
                addresses[pid] = (ip, port)
        # print(addresses)
        assert all([node is not None for node in addresses])
        print("hosts.config is correctly read")
        instantiate_hbbft_node(sid, i, B, N, f, addresses, K)
    except FileNotFoundError or AssertionError as e:
        #print(e)
        traceback.print_exc()
        #print("hosts.config is not correctly read... ")
        #host = "127.0.0.1"
        #port_base = int(rnd.random() * 5 + 1) * 10000
        #addresses = [(host, port_base + 200 * i) for i in range(N)]
        #print(addresses)
    #instantiate_hbbft_node(sid, i, B, N, f, addresses, K)
