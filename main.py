from ArgumentParser import get_arguments
from ASCIIArt import plumber_ascii_art
import os
import json
import logging.config


def setup_logging(default_path='logging.json', default_level=logging.INFO, env_key='LOG_CFG'):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
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
    if args.client:
        logger.info("starting client..")
        pass
    if args.server:
        logger.info("starting server..")
        pass


if __name__ == "__main__":
    main()

















"""




server_addr = '188.166.148.53'

if enable_log:
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s - %(message)s',
                        filename=log_file,
                        filemode='a')
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)-5s %(lineno)-3d - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)





echo  1  > /proc/sys/net/ipv4/icmp_echo_ignore_all

a = PlumberDataTypes.AckPacket()
print "test"
pass

"""



