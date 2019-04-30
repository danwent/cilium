#!/usr/bin/python
#
# tcpv4connect	Trace TCP IPv4 connect()s.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4connect [-h] [-t] [-p PID]
#
# This is provided as a basic example of TCP connection & socket tracing.
#
# All IPv4 connection attempts are traced, even if they ultimately fail.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from subprocess import check_output
import datetime
import docker
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

        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        u32 parent_pid = task->real_parent->tgid;
	bpf_trace_printk("trace_tcp4connect_ppid %d\\n", parent_pid);

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
	bpf_trace_printk("trace_tcp4connect_tuple %x %d %d\\n", saddr, ntohs(sport), ntohs(dport));

	currsock.delete(&pid);

	return 0;
}

int kretprobe___do_fork(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        u32 parent_pid = task->real_parent->tgid;
	bpf_trace_printk("trace__do_fork %d %d\\n", parent_pid, ret);
        return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

def get_pid(name):
    return int(check_output(["pidof","-s",name]))

def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

pid_tree_map = {}
pid_to_identity_map = {}
containerd_children_map = {}
tuple_to_identity_map = {}


def update_pid_tree_map(current_pid, parent_pid):
    #print ("update_pid_tree_map called %s %s\n" % (current_pid, parent_pid))
    if parent_pid == containerd_pid:
        containerd_children_map[current_pid] = 0
        #print ("containerd child pid %s\n" % (current_pid))
    if parent_pid in containerd_children_map:
        pid_tree_map[current_pid] = current_pid  # top-level entry
        #print ("top-level pid_tree_map entry %s %s\n" % (current_pid, current_pid))
    elif parent_pid in pid_tree_map:
        pid_tree_map[current_pid] = pid_tree_map[parent_pid]
        #print ("normal pid_tree_map entry %s %s\n" % (current_pid, pid_tree_map[parent_pid]))


# TODO: ensure this is the containerd-shim that is descended from
# init (pid 1) -> /usr/local/bin/containerd -> containerd-shim

containerd_pid = get_pid("containerd")

print ("Using containerd pid of %d\n" % (containerd_pid))

docker_client = docker.from_env()
docker_api_client = docker.APIClient(base_url='unix://var/run/docker.sock')

last_event_time = datetime.datetime.now()

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer


class MainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        length = int(self.headers.getheader('content-length'))
        line = self.rfile.read(length)
        print("request: '%s'\n" % line)
        self.send_response(200)
        self.send_header("Content-type","application/json")
        self.end_headers()
        if line in tuple_to_identity_map:
            print("returning identity info '%s'" % tuple_to_identity_map[line])
            self.wfile.write(json.dumps(tuple_to_identity_map[line]))
        else:
            print("return empty result")
            self.wfile.write("{}")
        return


server = HTTPServer(("0.0.0.0", 9999), MainHandler)
thread = threading.Thread(target = server.serve_forever)
thread.daemon = True
thread.start()


# filter and format output
while 1:
	# Read messages from kernel pipe
	try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            now = datetime.datetime.now()
            #hack: read docker events only if there has been a new trace event
            for event in docker_client.events(since=last_event_time, until=now, decode=True):
                #print (event, "\n")
                if event['Action'] == "start":

                    container_id = event['id']
                    container_details = docker_api_client.inspect_container(container_id)
                    pid = container_details['State']['Pid']
                    identity_info = {
                        "type" : "run",
                        "container_name": container_details['Name'],
                        "container_image": container_details['Config']['Image'],
                        "container_id": container_id,
                        "entrypoint": container_details['Config']['Entrypoint'],
                        "privileged": container_details['HostConfig']['Privileged']
                    }
                    pid_to_identity_map[pid] = identity_info
                    #print ("new pid => identity mapping (%s %s, %s, %s)" % (pid, identity_info['type'],
                    #            identity_info['container_name'], identity_info['entrypoint']))
                elif event['Action'].startswith("exec_start"):
                    exec_id = event['Actor']['Attributes']['execID']
                    exec_details = docker_api_client.exec_inspect(exec_id)
                    pid = exec_details['Pid']
                    identity_info = {
                        "type" : "exec",
                        "container_name": event['Actor']['Attributes']['name'],
                        "container_image": event['Actor']['Attributes']['image'],
                        "container_id": event['Actor']['ID'],
                        "entrypoint": exec_details['ProcessConfig']['entrypoint'],
                        "privileged": exec_details['ProcessConfig']['privileged']
                    }
                    pid_to_identity_map[pid] = identity_info
                    #print ("new pid => identity mapping (%s %s, %s, %s)" % (pid, identity_info['type'],
                    #            identity_info['container_name'], identity_info['entrypoint']))

            last_event_time = now

            # now interpret trace data.  Can't really assume that we have the
            # docker event by now though.

            if msg.startswith(b"trace_tcp4connect_tuple"):
                (_tag, saddr_hs, sport_s, dport_s) = msg.split(b" ")
                printb(b"CTUPLE: (pid=%-6d) (comm=%-12.12s) (saddr=%-16s) (sport=%-4s) (dport=%-4s)" % (pid, task,
	            inet_ntoa(int(saddr_hs, 16)), sport_s, dport_s))
                if pid in pid_tree_map:
                    root_pid = pid_tree_map[pid]
                    print("Root PID for connect: %d\n" % (root_pid))
                    if root_pid in pid_to_identity_map:
                        tuple_str = inet_ntoa(int(saddr_hs, 16)) + ":" + str(sport_s)
                        print ("Identity Info Mapping: %s => %s \n" %
                                    (tuple_str, pid_to_identity_map[root_pid]))
                        tuple_to_identity_map[tuple_str] = pid_to_identity_map[root_pid]
                else:
                    print("No root pid found for connect\n")
            elif msg.startswith(b"trace_tcp4connect_ppid"):
                (_tag, parent_pid) = msg.split(b" ")
                update_pid_tree_map(int(pid), int(parent_pid))
                #printb(b"CPARENT: (pid=%-6d) (comm=%-12.12s) (ppid=%-4s)" % (pid, task, parent_pid))
            elif msg.startswith(b"trace__do_fork"):
                (_tag, parent_pid, child_pid) = msg.split(b" ")
                update_pid_tree_map(int(pid), int(parent_pid))
                #printb(b"FORK: (pid=%-6d) (comm=%-12.12s) (ppid=%-4s) (cpid=%-4s)" % (pid, task, parent_pid, child_pid))


	except KeyboardInterrupt:
	    exit()
