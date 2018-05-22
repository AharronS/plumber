from ArgumentParser import get_arguments
from ASCIIArt import plumber_ascii_art
import os
import json
import logging.config
import platform
import sys
from PlumberServer import Server
from PlumberClient import Client

current_os = platform.system()
support_os = ('Linux')


def check_os_support():
    if not support_os.__contains__(current_os):
        print 'Not support in %s' % current_os
        sys.exit()


def setup_logging(default_path='logging.json', default_level=logging.INFO, env_key='LOG_CFG'):
    path = default_path
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


def main():
    setup_logging()
    logger = logging.getLogger()
    args = get_arguments()
    print(plumber_ascii_art)
    check_os_support()
    if args.client:
        logger.info("starting client..")
        Client.start_client(args.host, args.port, args.proxy_addr)
    if args.server:
        logger.info("starting server..")
        Server.start_server(args.host, args.port, args.users, args.passwords)


if __name__ == "__main__":
    main()

















"""




server_addr = '188.166.148.53'


echo  1  > /proc/sys/net/ipv4/icmp_echo_ignore_all

a = PlumberDataTypes.AckPacket()
print "test"
pass

"""



