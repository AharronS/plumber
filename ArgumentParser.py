import argparse


class UserAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(namespace.passwords) < len(namespace.users):
            parser.error('Missing password')
        else:
            namespace.users.append(values)


class PasswordAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(namespace.users) <= len(namespace.passwords):
            parser.error('Missing user')
        else:
            namespace.passwords.append(values)


def get_arguments():
    parser = argparse.ArgumentParser(description='Plumber - tunnel your data via socks over ICMP')

    parser.add_argument('--password', dest='passwords', default=[], action=PasswordAction,
                        help="Set a password (or passwords) for the proxy server")
    parser.add_argument('--user', dest='users', default=[], action=UserAction,
                        help="Set a user (s) allowed to the proxy server")
    parser.add_argument('--server', action="store_true", dest="server", default=False,
                        help="If you want to run Plumber as a server")
    parser.add_argument('--client', action="store_true", dest="client", default=False,
                        help="If you want to run Plumber as a client")
    parser.add_argument('--port', action="store", dest="port", required=True,
                        type=int, help="Specify port number for listening")
    parser.add_argument('--host', action="store", dest="host", required=True, default="localhost",
                        type=str, help="Specify port number for listening")
    parser.add_argument('--proxy_addr', action="store", dest="proxy_addr",
                        type=str, help="Specify a proxy server adress to for the tunnel")
    parser.add_argument('--allowed_ip', dest='allowed_ip', default=[], action="append",
                        help="set allowed IP list")
    parser.add_argument('--version', action='version', version='Plumber 1.0')

    args = parser.parse_args()

    if (not args.server) and (not args.client):
        parser.error("You must specify a server or client")
    if args.server and args.client:
        parser.error("You must select a server or client")
    if args.client and not args.proxy_addr:
        parser.error("You must specify proxy server address")
    if args.port not in range(23, 65535):
        parser.error("port number must be in range 23-65535")

    return args
