from SocksServer.Client import Client
from SocksServer.Server import Server
from SocksServer import secretsocks
import threading


def start_fake_remote():
    Server('127.0.0.1', 8080)


if __name__ == '__main__':
    # Set secretsocks into debug mode
    secretsocks.set_debug(True)

    # Create a server object in its own thread
    print('Starting the fake remote server...')
    t = threading.Thread(target=start_fake_remote)
    t.daemon = True
    t.start()

    # Create the client object
    print('Creating a the client...')
    client = Client('127.0.0.1', 8080)

    # Start the standard listener with our client
    print('Starting socks server...')
    listener = secretsocks.Listener(client, host='127.0.0.1', port=1080)
    listener.wait()