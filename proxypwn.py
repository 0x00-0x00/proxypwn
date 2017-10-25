#!/usr/bin/env python
from sys import exit, stderr
from argparse import ArgumentParser
from time import sleep
from netaddr import IPNetwork
from pwn import info
from hashlib import md5
from random import randint
from multiprocessing import cpu_count
from os import kill
from subprocess import *
from threading import *
from socket import *


# STATIC GLOBAL OBJECTS
class ThreadPool(object):
    def __init__(self):
        super(ThreadPool, self).__init__()
        self.active = []
        self.lock = Lock()
    def makeActive(self, name):
        with self.lock:
            self.active.append(name)
    def makeInactive(self, name):
        with self.lock:
            self.active.remove(name)

# STATIC GLOBAL VARIABLES
DEFAULT_TIMEOUT = 15

# STATIC GLOBAL FUNCTIONS
write = stderr.write
flush = stderr.flush


class Tunnel(object):
    def __init__(self, proxy_info, conn_info, base_num):
        """
        param: (str, int), (str, int)
        """
        if len(proxy_info) < 2:
            raise Exception("Invalid proxy information for tunneling")
        if len(conn_info) < 2:
            raise Exceptio("invalid target information for tunneling")

        # proxy arguments
        self.proxy_addr = proxy_info[0]
        self.proxy_port = proxy_info[1]

        # target arguments
        self.host_addr = conn_info[0].__str__()
        self.port = conn_info[1]

        if self.port > 30000:
            base_num = 1024

        # localhost arguments
        self.tunnel_port = base_num + self.port
        if self.tunnel_port > 65535:
            self.tunnel_port = randint(60000,65534)

        self.pid = None  # control all the pids
        self.is_active = None

        # start the pwnage!!!!
        self._create_tunnel()

    def _check_tunnel(self):
        """
        Check if the tunnel is open and return a boolean value.
        """
        sleep(DEFAULT_TIMEOUT / 3)
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        try:
            sock.connect(("127.0.0.1", self.tunnel_port))
            return True
        except Exception as e:
            return False

    def _create_tunnel(self):
        """
        Creates a TCP tunnel for a certain port using proxytunnel.
        """
        proc = Popen(["proxytunnel", "-p",
            ':'.join([self.proxy_addr, str(self.proxy_port)]),
            '-d', ':'.join([self.host_addr, str(self.port)]),
            '-a', str(self.tunnel_port)], stdout=PIPE, stderr=PIPE, shell=False)

        if self._check_tunnel() is True:
            info("Tunneling established: {0}:{1} <---> {2}:{3} <---> you:{4}".format(self.host_addr,
            self.port, self.proxy_addr, self.proxy_port, self.tunnel_port))
            self.is_active = True
            self.pid = proc.pid
        else:
            info("Tunneling failed.")

    def close(self):
        """
        Kills an open TCP tunnel proccess.
        """
        if type(self.pid) is not int or self.pid < 1:
            info("Tunnel proccess pid is not set.  [{0}:{1}]".format(
                self.host_addr, self.port))
        info("Killing tunnel for {0}:{1}".format(self.host_addr, self.port))
        try:
            kill(self.pid, 9)
            return True
        except Exception as e:
            info("Could not kill tunnel proccess!")
            return None


class SquidScanner(object):
    def __init__(self, target, ip_range, error_string, prange, tunnel_bool, creds):
        """
        param str, str, str, (int, int)
        """
        self.start_port = prange[0]
        self.end_port =  prange[1]
        self.base_num = randint(30000, 60000)

        self.target_ip, self.target_port = self._get_target_info(target)
        self.range = ip_range
        self.error_string = error_string
        self.open_ports = list()

        self.tunnel = tunnel_bool
        self.tunnels = list()

        self.username = None
        self.passwd = None
        if len(creds) > 1:
            self.username = creds[0]
            self.passwd = creds[1]

        self.scan_finished = False
        self._start()
        self.scan_finished = True

    def serve_tunnels(self):
        """
        Function to just hang execution to maintain children proccess
        alive.
        """
        while True:
            sleep(10)

    def _get_target_info(self, target):
        ip, port = target.split(":")
        return ip, port

    def _prod_port(self, conn_info):
        """
        param: (str, int) => (ip, port)
        """
        with semaphore:
            name = currentThread().getName()
            pool.makeActive(name)
            ip, port = conn_info
            if self.passwd is None:
                proc = Popen("curl --connect-timeout {0} -x '{1}:{2}' {3}:{4}".format(DEFAULT_TIMEOUT,
                    self.target_ip, self.target_port, ip, port), shell=True,
                stdout=PIPE, stderr=PIPE)
            else:
                proc = Popen("curl --connect-timeout {0} -x '{1}:{2}' {3}:{4} --proxy-user '{5}:{6}'".format(DEFAULT_TIMEOUT,
                    self.target_ip, self.target_port, ip, port, self.username, self.passwd), shell=True,
                    stdout=PIPE, stderr=PIPE)
            stdout, stderr = proc.communicate()
            for err in self.error_string.split(","):
                if err.lower() in stdout.lower():
                    pool.makeInactive(name)
                    return None
            info("Open port: {0}".format(port))
            self.open_ports.append(port)
            if self.tunnel is True:
                tunnel = Tunnel( (self.target_ip, self.target_port), (ip, port),
                        self.base_num) # creates a TCP tunnel
                self.tunnels.append(tunnel) # register the tunnel
            pool.makeInactive(name)
        return port

    def _start(self):
        for ip_addr in IPNetwork(self.range):
            print("")
            info("Scanning host {0} for port range {1}-{2}".format(ip_addr, self.start_port, self.end_port))
            for port in range(self.start_port, self.end_port):
                thr = Thread(target=self._prod_port, args=((ip_addr, port),),
                        name="portscan_{0}".format(port))
                thr.start()
                write("Scanning port: {0}  \r".format(port))
        return None


if __name__ == "__main__":
    info("ProxyPwn - zc00l super proxy pivot scanning/tunneling script")
    parser = ArgumentParser()
    parser.add_argument("--target", help="Squid IP:port", required=True)
    parser.add_argument("--range", help="IP network range to scan.", required=True)
    parser.add_argument("--error-string", help="Error string",
            type=str, default="denied,fail")
    parser.add_argument("--port-range", help="Port range to scan in format: X,Y",
            type=str, default="1,1024")
    parser.add_argument("--threads", help="How many threads to use", type=int,
            default=cpu_count())
    parser.add_argument("--tunnel", help="Establish TCP tunnels.", required=False,
            default=False, action="store_true")
    parser.add_argument("--username", help="Username to use at Proxy", required=False,
            type=str)
    parser.add_argument("--password", help="Password to use at the Proxy", required=False,
            type=str)

    args = parser.parse_args()
    if ":" not in args.target:
        info("--target parameter need to be in the following format:  IP:PORT")
        exit(1)
    pool = ThreadPool()
    semaphore = Semaphore(args.threads)

    try:
        prange = [int(x) for x in args.port_range.split(",")]
        if len(prange) != 2:
            raise Exception("Invalid port range")
    except Exception:
        print("Error on validating port range to scan.")
        exit(1)

    try:
        scanner = SquidScanner(args.target, args.range, args.error_string, prange, args.tunnel, (args.username, args.password))
        sleep(DEFAULT_TIMEOUT)
        while scanner.scan_finished is not True:
            sleep(DEFAULT_TIMEOUT)
        if len(scanner.tunnels) > 0:
            info("Serving tunnels ...")
            scanner.serve_tunnels() # serve tunnels

    except KeyboardInterrupt:
        if len(scanner.tunnels) > 0:
            closed = 0
            for tunnel in scanner.tunnels:
                if tunnel.close() is True:
                    closed += 1
            info("Closed {0} TCP tunnels.".format(closed))
    print("")


