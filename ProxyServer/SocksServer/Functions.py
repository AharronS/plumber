from ..SocksServer import *
import logging
import signal
import sys
import os
import platform

current_os = platform.system()
support_os = ('Linux')


def byte_to_int(b):
    """
    Convert Unsigned byte to int
    :param b: byte value
    :return:  int value
    """
    return b & 0xFF


def port_from_byte(b1, b2):
    """

    :param b1: First byte of port
    :param b2: Second byte of port
    :return: Port in Int
    """
    return byte_to_int(b1) << 8 | byte_to_int(b2)


def host_from_ip(a, b, c, d):
    a = byte_to_int(a)
    b = byte_to_int(b)
    c = byte_to_int(c)
    d = byte_to_int(d)
    return "%d.%d.%d.%d" % (a, b, c, d)


def get_command_name(value):
    """
    Gets command name by value
    :param value:  value of Command
    :return: Command Name
    """
    if value == 1:
        return 'CONNECT'
    elif value == 2:
        return 'BIND'
    elif value == 3:
        return 'UDP_ASSOCIATE'
    else:
        return None


def build_command_response(reply):
    start = b'\x05%s\x00\x01\x00\x00\x00\x00\x00\x00'
    return start % reply.get_byte_string()


def close_session(session):
    session.get_client_socket().close()
    logging.info("Session[%s] closed" % session.get_id())


def run_daemon_process(stdout='/dev/null', stderr=None, stdin='/dev/null',
                       pid_file=None, start_msg='started with pid %s'):
    """
         This forks the current process into a daemon.
         The stdin, stdout, and stderr arguments are file names that
         will be opened and be used to replace the standard file descriptors
         in sys.stdin, sys.stdout, and sys.stderr.
         These arguments are optional and default to /dev/null.
        Note that stderr is opened unbuffered, so
        if it shares a file with stdout then interleaved output
         may not appear in the order that you expect.
    """
    # flush io
    sys.stdout.flush()
    sys.stderr.flush()
    # Do first fork.
    try:
        if os.fork() > 0:
            sys.exit(0)  # Exit first parent.
    except OSError, e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()
    # Do second fork.
    try:
        if os.fork() > 0:
            sys.exit(0)  # Exit second parent.
    except OSError, e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
    # Open file descriptors and print start message
    if not stderr:
        stderr = stdout
        si = file(stdin, 'r')
        so = file(stdout, 'a+')
        se = file(stderr, 'a+', 0)  # unbuffered
        pid = str(os.getpid())
        sys.stderr.write(start_msg % pid)
        sys.stderr.flush()
    if pid_file:
        file(pid_file, 'w+').write("%s\n" % pid)
    # Redirect standard file descriptors.
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

def check_os_support():
    if not support_os.__contains__(current_os):
        print 'Not support in %s' % current_os
        sys.exit()


def stop(pid_file):
    check_os_support()
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
    check_os_support()
    try:
        f = open(pid_file, 'r')
        pid = int(f.readline())
        print 'pysocks(pid %d) is running...' % pid
    except IOError:
        print "pysocks is stopped"


def stop_proxy():
    user_home = os.path.expanduser('~')
    pid_file = user_home + '/.pysocks.pid'
    stop(pid_file)


def main():
    port = 1080
    enable_log = True
    log_file = 'socks.log'
    auth = False
    user_home = os.path.expanduser('~')
    pid_file = user_home + '/.pysocks.pid'
    user_manager = UserManager()
    allowed_ips = None

    if sys.argv.__len__() < 2:
        sys.exit()

    command = sys.argv[1]
    if command == 'start':
        pass
    elif command == 'stop':
        stop(pid_file)
        sys.exit()
    elif command == 'restart':
        stop(pid_file)
    elif command == 'status':
        status(pid_file)
        sys.exit()
    else:
        sys.exit()

    for arg in sys.argv[2:]:
        if arg.startswith('--port='):
            try:
                port = int(arg.split('=')[1])
            except ValueError:
                print '--port=<val>  <val> should be a number'
                sys.exit()
        elif arg.startswith('--auth'):
            auth = True
            users = arg.split('=')[1]
            for user in users.split(','):
                user_pwd = user.split(':')
                user_manager.add_user(User(user_pwd[0], user_pwd[1]))
        elif arg == '-h':
            sys.exit()
        elif arg.startswith('--log='):
            value = arg.split('=')[1]
            if value == 'true':
                enable_log = True
            elif value == 'false':
                enable_log = False
            else:
                print '--log=<val>  <val> should be true or false'
                sys.exit()
        elif arg.startswith('--allowed='):
            value = arg.split('=')[1]
            allowed_ips = value.split(',')
        else:
            print 'Unknown argument:%s' % arg
            sys.exit()
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

    Socks5Server.allow_reuse_address = True
    socks5_server = Socks5Server(port, auth, user_manager, allowed=allowed_ips)
    try:
        if support_os.__contains__(current_os):
            run_daemon_process(pid_file=pid_file, start_msg='Start SOCKS5 server at pid %s\n')
        socks5_server.serve_forever()
    except KeyboardInterrupt:
        socks5_server.server_close()
        socks5_server.shutdown()
        logging.info("SOCKS5 server shutdown")


if __name__ == '__main__':
    main()