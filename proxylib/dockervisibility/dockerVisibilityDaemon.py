#!/usr/bin/python
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Borrowed significant code from BCC tcpv4connect.py

from __future__ import print_function
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from bcc import BPF
from bcc.utils import printb
from subprocess import check_output
import datetime
import docker
import time
import json
import socket
import SocketServer
import threading

# define BPF program
bpf_text = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u16 dport = skp->__sk_common.skc_dport;
        struct inet_sock *sockp = (struct inet_sock *)skp;
        u16 sport = sockp->inet_sport;

	// output
	bpf_trace_printk("trace_tcp4connect_tuple %x %d %d\\n", saddr, ntohs(sport), pid);

	currsock.delete(&pid);

	return 0;
}

int kretprobe__alloc_pid(struct pt_regs *ctx)
{
	u32 parent_pid = bpf_get_current_pid_tgid();
	struct pid *pid = (struct pid *) PT_REGS_RC(ctx);
    bpf_trace_printk("alloc_pid %d %d\\n", parent_pid, pid->numbers[0].nr);
    return 0;
}


"""

pid_tree_map = {}
pid_to_identity_map = {}
tuple_to_identity_map = {}


class MainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        length = int(self.headers.getheader('content-length'))
        line = self.rfile.read(length)
        print("request: '%s'\n" % line)
        self.send_response(200)
        self.send_header("Content-type","application/json")
        self.end_headers()
        i = 0
        found = False
        while i < 10:
            if line in tuple_to_identity_map:
                print("returning identity info '%s'" % tuple_to_identity_map[line])
                self.wfile.write(json.dumps(tuple_to_identity_map[line]))
                found = True
                break
            time.sleep(0.2)
            i = i + 1

        if not found:
            print("unable to file match, returning empty result")
            self.wfile.write("{}")
        return


server = HTTPServer(("0.0.0.0", 9999), MainHandler)
thread = threading.Thread(target = server.serve_forever)
thread.daemon = True
thread.start()

# initialize BPF
b = BPF(text=bpf_text)


def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

docker_client = docker.from_env()
docker_api_client = docker.APIClient(base_url='unix://var/run/docker.sock')

last_event_time = datetime.datetime.now()

to_resolve_list = []
existing_ips = {}

# filter and format output
while 1:
    # Read messages from kernel pipe
    try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            now = datetime.datetime.now()
            #hack: read docker events only if there has been a new trace event
            for event in docker_client.events(since=last_event_time, until=now, decode=True):
                print (event, "\n")
                if event['Action'] == "start":

                    container_id = event['id']
                    container_details = docker_api_client.inspect_container(container_id)
                    pid = container_details['State']['Pid']
                    print ("Pid from docker inspect container '%s'" % pid)
                    identity_info = {
                        "type" : "run",
                        "container_name": container_details['Name'],
                        "container_image": container_details['Config']['Image'],
                        "container_id": container_id,
                        "entrypoint": container_details['Config']['Entrypoint'][0],
                        "privileged": container_details['HostConfig']['Privileged']
                    }
                    pid_to_identity_map[int(pid)] = identity_info
                    print ("new pid => identity mapping (%s %s, %s, %s)" % (pid, identity_info['type'],
                                identity_info['container_name'], identity_info['entrypoint']))
                elif event['Action'].startswith("exec_start"):
                    if 'execID' in event['Actor']['Attributes']:
                        exec_id = event['Actor']['Attributes']['execID']
                        exec_details = docker_api_client.exec_inspect(exec_id)
                        pid = exec_details['Pid']
                        print ("Pid from docker inspect exec '%s'" % pid)
                        identity_info = {
                            "type" : "exec",
                            "container_name": event['Actor']['Attributes']['name'],
                            "container_image": event['Actor']['Attributes']['image'],
                            "container_id": event['Actor']['ID'],
                            "entrypoint": exec_details['ProcessConfig']['entrypoint'],
                            "privileged": exec_details['ProcessConfig']['privileged']
                        }
                        pid_to_identity_map[int(pid)] = identity_info
                        print ("new pid => identity mapping (%s %s, %s, %s)" % (pid, identity_info['type'],
                                    identity_info['container_name'], identity_info['entrypoint']))
                    else:
                        # hapens with older versions of docker
                        print("no execID found for exec_start event")
            last_event_time = now

            new_to_resolve_list = []
            for (rpid, rtuple, rattempts) in to_resolve_list:
                test_pid = rpid
                print ("lookup for %s starting with test_pid : %s \n" % (rtuple, test_pid))
                found = False
                while 1:
                    if test_pid in pid_to_identity_map:
                        print ("Connection Identity Info (%s) : %s => %s \n" %
                                    (rpid, rtuple, pid_to_identity_map[test_pid]))
                        tuple_to_identity_map[rtuple] = pid_to_identity_map[test_pid]
                        found = True
                        break

                    if test_pid in pid_tree_map:
                        test_pid = pid_tree_map[test_pid]
                        print ("next test_pid %s" % (test_pid))
                    else:
                        print("No Connection Identity info found for connection (pid %s) (tuple %s) (attempt %d)"
                                % (rpid, rtuple, rattempts))
                        break
                if not found and rattempts < 200:
                    new_to_resolve_list.append((rpid, rtuple, (rattempts + 1)))

            to_resolve_list = new_to_resolve_list

            # now interpret trace data.  Can't really assume that we have the
            # docker event by now though.

            if msg.startswith(b"trace_tcp4connect_tuple"):
                (_tag, saddr_hs, sport_s, pid2) = msg.split(b" ")
                printb(b"CTUPLE: (pid=%-4s) (comm=%-12.12s) (saddr=%-16s) (sport=%-4s) (pid2=%-4s)" % (pid2, task,
	            inet_ntoa(int(saddr_hs, 16)), sport_s, pid2))
                #print ("identity lookup with pid_to_identity_map: %s\n" % (pid_to_identity_map))
                #print ("identity lookup with pid_tree_map: %s\n" % (pid_tree_map))
                tuple_str = inet_ntoa(int(saddr_hs, 16)) + ":" + str(sport_s)
                to_resolve_list.append((int(pid2), tuple_str, 0))

                # hack to try and get the docker notifications if we
                # ever see a new IP.  Won't work with IP recycling
                ip = inet_ntoa(int(saddr_hs, 16))
                if ip not in existing_ips:
                    existing_ips[ip] = ""
                    time.sleep(0.5)

            elif msg.startswith(b"alloc_pid "):
                (_tag, parent_pid, child_pid) = msg.split(b" ")
                pid_tree_map[int(child_pid)] = int(parent_pid)
                printb(b"ALLOC: (pid=%-4s) (comm=%-12.12s) (child_pid=%-4s) " % (parent_pid, task, child_pid))


    except KeyboardInterrupt:
        exit()
