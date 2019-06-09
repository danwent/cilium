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
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack

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

struct ipv4_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct alloc_pid_event_t {
    u32 parent_pid;
    u32 child_pid;
};

struct free_pid_event_t {
    u32 freed_pid;
};

struct exec_event_t {
    u32 pid;
    char exec_fname[128];
};

BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(alloc_pid_events);
BPF_PERF_OUTPUT(free_pid_events);
BPF_PERF_OUTPUT(exec_events);

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
	u16 dport = skp->__sk_common.skc_dport;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;

    struct ipv4_event_t data4 = {.pid = pid};
    data4.saddr = skp->__sk_common.skc_rcv_saddr;
    data4.daddr = skp->__sk_common.skc_daddr;
    data4.sport = ntohs(sport);
    data4.dport = ntohs(dport);
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

	currsock.delete(&pid);

	return 0;
}

int kprobe__free_pid(struct pt_regs *ctx, struct pid *pid){
    struct free_pid_event_t data = {};
    data.freed_pid = pid->numbers[0].nr;
    free_pid_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kretprobe__alloc_pid(struct pt_regs *ctx)
{
    struct alloc_pid_event_t data = {};
	struct pid *pid = (struct pid *) PT_REGS_RC(ctx);

    data.parent_pid = bpf_get_current_pid_tgid();
    data.child_pid = pid->numbers[0].nr;
    alloc_pid_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct exec_event_t data = {};
	data.pid = bpf_get_current_pid_tgid();
    bpf_probe_read(data.exec_fname, sizeof(data.exec_fname), filename);
    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

unix_session = requests_unixsocket.Session()

pid_tree_map = {}
rootpid_to_identity_map = {}
rootpid_to_containerinfo_map = {}

# once a pid is deallocated, it will be removed from
# rootpid_to_containerinfo_map.   Need to keep a reference to it.
containerinfo_perm_list = []

tuple_to_identity_map = {}
tuple_age_map = {}
pid_free_time_map = {}
pid_to_execfname_map = {}

class MainHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        url = urlparse.urlparse(self.path)

        if url.path.startswith("/containerinfo.json"):
            print("containerinfo request")
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps([x.get_info() for x in containerinfo_perm_list]))

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
        self.exec_paths = {}
        self.rootpid = rootpid
        self.identity_info = identity_info

    def get_info(self):
        return {
            "container_name": self.identity_info['container_name'],
            "rootpid": self.rootpid,
            "identity_info": self.identity_info,
            "outbound_connections": self.outbound_connections.values(),
            "exec_paths": self.exec_paths.keys()
        }

class EventPidToResolve:

    # valid types = ("conn_tuple", "exec_fname", "pid_free")

    def __init__(self, child_pid, type, info):
        self.child_pid = child_pid
        self.type = type
        self.info = info
        self.attempts = 0

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
                # don't show 'cidr', 'reserved', or other 'io.cilium' labels
                label_list = [ l for l in cilium_id_info["labels"] if "io.cilium" not in l and "cidr:" not in l and "reserved:" not in l]

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

                    ci = ContainerInfo(int(pid), identity_info)
                    rootpid_to_containerinfo_map[int(pid)] = ci
                    containerinfo_perm_list.append(ci)

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
                        ci = ContainerInfo(int(epid), identity_info)
                        rootpid_to_containerinfo_map[int(epid)] = ci
                        containerinfo_perm_list.append(ci)

                        #print ("new pid => identity mapping (%s %s, %s, %s)" % (epid, identity_info['type'],
                        #            identity_info['container_name'], identity_info['entrypoint']))
                    else:
                        # hapens with older versions of docker
                        print("no execID found for exec_start event")


            last_event_time = now

            new_to_resolve_list = []
            for ent in to_resolve_list:

                # garbage collect old map entries
                if ent.type == "free_pid":
                    if ent.attempts < 200:
                        ent.attempts = ent.attempts + 1
                        new_to_resolve_list.append(ent)
                    else:
                        p = int(ent.child_pid)
                        if p in pid_tree_map:
                            del pid_tree_map[p]
                        if p in rootpid_to_identity_map:
                            del rootpid_to_identity_map[p]
                        if p in rootpid_to_containerinfo_map:
                            del rootpid_to_containerinfo_map[p]
                        if p in pid_to_execfname_map:
                            del pid_to_execfname_map[p]
                    continue


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

                        if ent.type == "conn_tuple":
                            (src_tuple_str, dst_tuple_str) = ent.info.split("_")
                            # TODO: make tuple -> identity mapping based on full 4-tuple
                            tuple_to_identity_map[src_tuple_str] = rootpid_to_identity_map[test_pid]
                            tuple_age_map[src_tuple_str] = int(time.time())
                            (dst_ip_str, dst_port_str) = dst_tuple_str.split(":")
                            (dst_dns, dst_labels) = get_cilium_identity_info(dst_ip_str, int(dst_port_str))
                            containerinfo.outbound_connections[dst_dns + ":" + dst_port_str] = {
                                    "port": int(dst_port_str),
                                    "dns": dst_dns,
                                    "labels": dst_labels
                            }
                        elif ent.type == "exec_fname":
                            if len(exec_str) > 0:
                                containerinfo.exec_paths[exec_str] = ""

                        found = True
                        break

                    if test_pid in pid_tree_map:
                        test_pid = pid_tree_map[test_pid]
                    else:
                        break
                if not found and ent.attempts < 200:
                    ent.attempts = ent.attempts + 1
                    new_to_resolve_list.append(ent)

            to_resolve_list = new_to_resolve_list

            # age out old src-tuple info
            # should really do this only when client sock is closed
            now = int(time.time())
            for ts, created_time in tuple_age_map.iteritems():
                if (now - created_time) > 3600:
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

def process_conn_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    saddr_str = inet_ntop(AF_INET, pack("I", event.saddr)).encode()
    daddr_str = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    tuple_str = saddr_str + ":" + str(event.sport) + "_" + daddr_str + ":" + str(event.dport)
    #printb(b"CTUPLE: (pid=%-4s) : %s" % (event.pid, tuple_str))

    to_resolve = EventPidToResolve(event.pid, "conn_tuple", tuple_str)
    to_resolve_list.append(to_resolve)

def process_alloc_pid_event(cpu, data, size):
    event = b["alloc_pid_events"].event(data)
    pid_tree_map[int(event.child_pid)] = int(event.parent_pid)
    #printb(b"ALLOC_PID: (parent_pid=%-4s) (child_pid=%-4s) " % (event.parent_pid, event.child_pid))

def process_free_pid_event(cpu, data, size):
    event = b["free_pid_events"].event(data)
    #printb(b"FREE_PID: (pid=%-4s) " % (event.freed_pid))
    to_resolve = EventPidToResolve(int(event.freed_pid), "free_pid", "")
    to_resolve_list.append(to_resolve)

def process_exec_event(cpu, data, size):
    event = b["exec_events"].event(data)
    #printb(b"EXEC: (pid=%-4s) (exec_fname=%s) " % (event.pid, event.exec_fname))
    pid_to_execfname_map[int(event.pid)] = event.exec_fname
    to_resolve = EventPidToResolve(int(event.pid), "exec_fname", event.exec_fname)
    to_resolve_list.append(to_resolve)

b["ipv4_events"].open_perf_buffer(process_conn_event)
b["alloc_pid_events"].open_perf_buffer(process_alloc_pid_event)
b["free_pid_events"].open_perf_buffer(process_free_pid_event)
b["exec_events"].open_perf_buffer(process_exec_event)

# Main loop to watch for trace events

while 1:
    try:
            # non-blocking check of the event buffer
            b.perf_buffer_poll(timeout=100)

            print("SIZES:  len(to_resolve_list) = %d, len(pid_tree_map) = %d, len(rootpid_to_identity_map) = %d, len(rootpid_to_containerinfo_map) = %d  len(containerinfo_perm_list) = %d, len(tuple_to_identity_map) = %d, len(tuple_age_map) = %d, len(pid_to_execfname_map) = %d" % (len(to_resolve_list), len(pid_tree_map), len(rootpid_to_identity_map), len(rootpid_to_containerinfo_map), len(containerinfo_perm_list), len(tuple_to_identity_map), len(tuple_age_map), len(pid_to_execfname_map)))

    except KeyboardInterrupt:
        exit()
    except Exception as ex:
            logging.exception("Error in BPF watching thread")
