#!/usr/bin/python
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Borrowed significant code from BCC tcpv4connect.py
# https://github.com/iovisor/bcc/blob/master/examples/tracing/tcpv4connect.py
#
# Really need to update to properly use events rather than bpf_trace_printk

from __future__ import print_function
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from bcc import BPF
from bcc.utils import printb
from subprocess import check_output
import datetime
import time
import docker
import time
import json
import logging
import socket
import SocketServer
import threading
import urlparse
import requests_unixsocket

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
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;

	// TODO:  combine these into a single event to export
	bpf_trace_printk("trace_src_tcp4connect_tuple %x %d %d\\n", saddr, ntohs(sport), pid);
	bpf_trace_printk("trace_dst_tcp4connect_tuple %x %d %d\\n", daddr, ntohs(dport), pid);

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

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
	u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("exec %d %s\\n", pid, filename);
    return 0;
}

"""

unix_session = requests_unixsocket.Session()

pid_tree_map = {}
rootpid_to_identity_map = {}
rootpid_to_containerinfo_map = {}

tuple_to_identity_map = {}
tuple_age_map = {}
pid_to_execfname_map = {}

class MainHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        url = urlparse.urlparse(self.path)

        if url.path.startswith("/containerinfo.json"):
            print("containerinfo request")
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps([x.get_info() for x in rootpid_to_containerinfo_map.values()]))

        elif url.path.startswith("/lookup.json"):

            length = int(self.headers.getheader('content-length'))
            line = self.rfile.read(length)
            print("lookup request: '%s'" % line)
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
                print("unable to find match, returning empty result")
                self.wfile.write("{}")
        else:
            print("invalid request path: '%s'\n" % url.path)
            self.send_response(404)
            self.end_headers()

        return


server = HTTPServer(("0.0.0.0", 9999), MainHandler)
thread = threading.Thread(target = server.serve_forever)
thread.daemon = True
thread.start()

# initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

to_resolve_list = []

class ContainerInfo:

    def __init__(self, rootpid, identity_info):
        self.outbound_connections = {}
        self.listen_ports = {}
        self.exec_paths = {}
        self.rootpid = rootpid
        self.identity_info = identity_info

    def get_info(self):
        return {
            "container_name": self.identity_info['container_name'],
            "rootpid": self.rootpid,
            "identity_info": self.identity_info,
            "outbound_connections": self.outbound_connections.values(),
#           "listen_ports": self.listen_ports.keys(),
            "exec_paths": self.exec_paths.keys()
        }

class EventPidToResolve:

    # valid types = ("src_tuple", "dst_tuple", "listen_tuple", "exec_fname")

    def __init__(self, child_pid, type, info):
        self.child_pid = child_pid
        self.type = type
        self.info = info
        self.attempts = 0

def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

# returns a tuple of (dns-name, array of labels) for a given
# IP address used in a remote connection

def get_cilium_identity_info(ip_str, port):
    dns_name = ""
    label_list = []

    try:
        r = unix_session.get('http+unix://%2Fvar%2Frun%2Fcilium%2Fcilium.sock/v1/fqdn/cache?cidr=' + ip_str + "/32")
        if r.status_code == 200:
            # 404 if not found
            fqdn_list = r.json()
            if len(fqdn_list) > 0:
                dns_name = fqdn_list[0]["fqdn"]
    except:
        logging.exception("Error looking up DNS identity via cilium")

    # if its a cluster-ip, remap to a pod IP that backs it.
    try:
        r = unix_session.get('http+unix://%2Fvar%2Frun%2Fcilium%2Fcilium.sock/v1/service')
        service_list = r.json()
        for entry in service_list:

            if entry["spec"]["frontend-address"]["ip"] == ip_str and entry["spec"]["frontend-address"]["port"] == port:
                # just pick one for now
                if len(entry["spec"]["backend-addresses"]):
                    ip_str = entry["spec"]["backend-addresses"][0]["ip"]
                break
    except:
        logging.exception("Error looking up service via cilium")

    prefix_str = ip_str + "/32"
    try:
        sec_id = ""
        r = unix_session.get('http+unix://%2Fvar%2Frun%2Fcilium%2Fcilium.sock/v1/map/cilium_ipcache')
        cache = r.json()["cache"]
        for entry in cache:

            if entry["key"] == prefix_str:
                sec_id = entry["value"].split(" ")[0]
                break

        if len(sec_id) > 0:
            r = unix_session.get('http+unix://%2Fvar%2Frun%2Fcilium%2Fcilium.sock/v1/identity/' + sec_id)
            if r.status_code == 200:
                # 404 if not found
                cilium_id_info = r.json()
                label_list = [ l for l in cilium_id_info["labels"] if "io.cilium" not in l ]

    except:
        logging.exception("Error looking up label identity via cilium")

    return (dns_name, label_list)

def docker_event_watcher():
    global to_resolve_list

    docker_client = docker.from_env()
    docker_api_client = docker.APIClient(base_url='unix://var/run/docker.sock')
    last_event_time = datetime.datetime.now()

    while 1:
        try:
            now = datetime.datetime.now()
            for event in docker_client.events(since=last_event_time, until=now, decode=True):
                #print (event, "\n")
                if event['Action'] == "start":

                    container_id = event['id']
                    container_details = docker_api_client.inspect_container(container_id)
                    pid = container_details['State']['Pid']
                    #print ("Pid from docker inspect container '%s'" % pid)
                    #print ("container details = %s" % container_details)
                    entrypoint = ""
                    if container_details['Config']['Entrypoint']:
                        entrypoint = container_details['Config']['Entrypoint'][0]
                    identity_info = {
                        "type" : "run",
                        "container_name": container_details['Name'],
                        "container_image": container_details['Config']['Image'],
                        "container_id": container_id,
                        "entrypoint": entrypoint,
                        "privileged": container_details['HostConfig']['Privileged']
                    }
                    rootpid_to_identity_map[int(pid)] = identity_info
                    rootpid_to_containerinfo_map[int(pid)] = ContainerInfo(int(pid), identity_info)

                    #print ("new pid => identity mapping (%s %s, %s, %s)" % (pid, identity_info['type'],
                    #            identity_info['container_name'], identity_info['entrypoint']))
                elif event['Action'].startswith("exec_start"):
                    if 'execID' in event['Actor']['Attributes']:
                        exec_id = event['Actor']['Attributes']['execID']
                        exec_details = docker_api_client.exec_inspect(exec_id)
                        #print("exec details = %s" % str(exec_details))
                        epid = exec_details['Pid']
                        #print ("Pid from docker inspect exec '%s'" % epid)
                        identity_info = {
                            "type" : "exec",
                            "container_name": event['Actor']['Attributes']['name'],
                            "container_image": event['Actor']['Attributes']['image'],
                            "container_id": event['Actor']['ID'],
                            "entrypoint": exec_details['ProcessConfig']['entrypoint'],
                            "privileged": exec_details['ProcessConfig']['privileged']
                        }
                        rootpid_to_identity_map[int(epid)] = identity_info
                        rootpid_to_containerinfo_map[int(epid)] = ContainerInfo(int(epid), identity_info)
                        #print ("new pid => identity mapping (%s %s, %s, %s)" % (epid, identity_info['type'],
                        #            identity_info['container_name'], identity_info['entrypoint']))
                    else:
                        # hapens with older versions of docker
                        print("no execID found for exec_start event")
            last_event_time = now

            new_to_resolve_list = []
            for ent in to_resolve_list:
                test_pid = ent.child_pid
                found = False
                exec_str = ""

                while 1:
                    if ent.type == "exec_fname":

                        if test_pid in pid_to_execfname_map:
                            if len(exec_str) > 0:
                                exec_str = " : " + exec_str
                            exec_str = pid_to_execfname_map[test_pid] + exec_str

                    if test_pid in rootpid_to_identity_map:
                        containerinfo = rootpid_to_containerinfo_map[test_pid]

                        if ent.type == "src_tuple":
                            tuple_to_identity_map[ent.info] = rootpid_to_identity_map[test_pid]
                            tuple_age_map[tuple_str] = int(time.time())
                        elif ent.type == "exec_fname":
                            if len(exec_str) > 0:
                                containerinfo.exec_paths[exec_str] = ""
                        elif ent.type == "dst_tuple":
                            (ip_str, port_str) = ent.info.split(":")
                            (dest_dns, dest_labels) = get_cilium_identity_info(ip_str, int(port_str))
                            containerinfo.outbound_connections[dest_dns + ":" + port_str] = {
                                    "port": int(port_str),
                                    "dns": dest_dns,
                                    "labels": dest_labels
                            }
                        elif ent.type == "listen_tuple":
                            containerinfo.listen_ports[ent_info.split(":")[1]] = ""

                        found = True
                        break

                    if test_pid in pid_tree_map:
                        test_pid = pid_tree_map[test_pid]
                    else:
                        break
                if not found and ent.attempts < 200:
                    new_to_resolve_list.append(ent)

            to_resolve_list = new_to_resolve_list

            # age out old src-tuple info
            now = int(time.time())
            for ts, created_time in tuple_age_map.iteritems():
                if (now - created_time) > 10:
                    if ts in tuple_age_map:
                        del tuple_age_map[ts]
                    if ts in tuple_to_identity_map:
                        del tuple_to_identity_map[ts]

            time.sleep(0.05)

        except Exception as ex:
            logging.exception("Error in Docker resolution thread")

thread = threading.Thread(target = docker_event_watcher)
thread.daemon = True
thread.start()

# Main loop to watch for trace events

while 1:
    try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            #print("msg = '%s'" % msg)
            if msg.startswith(b"trace_src_tcp4connect_tuple"):
                (_tag, saddr_hs, sport_s, pid2) = msg.split(b" ")
                #printb(b"CTUPLE: (pid=%-4s) (comm=%-12.12s) (saddr=%-16s) (sport=%-4s) (pid2=%-4s)" % (pid2, task,
	            #                   inet_ntoa(int(saddr_hs, 16)), sport_s, pid2))
                tuple_str = inet_ntoa(int(saddr_hs, 16)) + ":" + str(sport_s)
                to_resolve = EventPidToResolve(int(pid2), "src_tuple", tuple_str)
                to_resolve_list.append(to_resolve)
            elif msg.startswith(b"trace_dst_tcp4connect_tuple"):
                (_tag, daddr_hs, dport_s, pid2) = msg.split(b" ")
                #printb(b"CTUPLE: (pid=%-4s) (comm=%-12.12s) (saddr=%-16s) (sport=%-4s) (pid2=%-4s)" % (pid2, task,
	            #                   inet_ntoa(int(daddr_hs, 16)), dport_s, pid2))
                tuple_str = inet_ntoa(int(daddr_hs, 16)) + ":" + str(dport_s)
                to_resolve = EventPidToResolve(int(pid2), "dst_tuple", tuple_str)
                to_resolve_list.append(to_resolve)
            elif msg.startswith(b"exec "):
                (_tag, pid2, exec_fname) = msg.split(b" ")
                #printb(b"EXEC: (pid=%-4s) (comm=%-12.12s) (pid2=%-4s) (exec_fname=%s) " % (pid2, task, pid2, exec_fname))
                pid_to_execfname_map[int(pid2)] = exec_fname
                to_resolve = EventPidToResolve(int(pid2), "exec_fname", exec_fname)
                to_resolve_list.append(to_resolve)
            elif msg.startswith(b"alloc_pid "):
                (_tag, parent_pid, child_pid) = msg.split(b" ")
                pid_tree_map[int(child_pid)] = int(parent_pid)
                #printb(b"ALLOC: (pid=%-4s) (comm=%-12.12s) (child_pid=%-4s) " % (parent_pid, task, child_pid))

    except KeyboardInterrupt:
        exit()
    except Exception as ex:
            logging.exception("Error in BPF watching thread")
