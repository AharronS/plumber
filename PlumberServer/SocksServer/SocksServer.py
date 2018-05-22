from SocksServerTools import *
import logging
import time


def stop(pid_file):
    print 'Stopping server...',
    try:
        f = open(pid_file, 'r')
        pid = int(f.readline())
        os.kill(pid, signal.SIGTERM)
        os.remove(pid_file)
        print "                 [OK]"
    except IOError:
        print "pysocks is not running"
    except OSError:
        print "pysocks is not running"


def status(pid_file):
    try:
        f = open(pid_file, 'r')
        pid = int(f.readline())
        print 'pysocks(pid %d) is running...' % pid
    except IOError:
        print "pysocks is stopped"


def check_if_up_and_kill(pid_file):
    try:
        f = open(pid_file, 'r')
        pid = int(f.readline())
        print 'pysocks(pid %d) is running...' % pid
        f.close()
        stop(pid_file)
        time.sleep(5)
    except IOError:
        print "pysocks not running"


def start_socks_server(port, users, passwords, allowed_ips):
    user_home = os.path.expanduser('~')
    pid_file = user_home + '/.pysocks.pid'
    auth = False
    user_manager = UserManager()
    check_if_up_and_kill(pid_file)
    for user, password in zip(users, passwords):
        user_manager.add_user(User(user, password))

    Socks5ServerObject.allow_reuse_address = True
    socks5_server = Socks5ServerObject(port, auth, user_manager, allowed=allowed_ips)
    try:
        run_daemon_process(pid_file=pid_file, start_msg='Start SOCKS5 server at pid %s\n')
        socks5_server.serve_forever()
    except KeyboardInterrupt:
        socks5_server.server_close()
        socks5_server.shutdown()
        logging.info("SOCKS5 server shutdown")


if __name__ == '__main__':
    start_socks_server(9011, ['username'], ['password'], None)
