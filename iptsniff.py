import ctypes as ct
from collections import OrderedDict
import ipaddress
import socket
import struct
import contextlib
import sys
import os
import time
from functools import partial

from iptc import ip4tc
from iptc import xtables

import bcc
from bcc import BPF


XT_TABLE_MAXNAMELEN = 32
IFNAMSIZ = 16
XT_EXTENSION_MAXNAMELEN = 29
NF_INET_NUMHOOKS = 5
HOOKNAMES = ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING']
XT_ERROR_TARGET = b'ERROR'
XT_STANDARD_TARGET = b""

NF_DROP = 0
NF_ACCEPT = 1
NF_STOLEN = 2
NF_QUEUE = 3
NF_REPEAT = 4 # RETURN
NF_STOP = 5	# Deprecated, for userspace nf_queue compatibility.
NF_MAX_VERDICT = NF_STOP

STANDARD_VERDICT = {
    -NF_REPEAT-1: 'RETURN',
    -NF_ACCEPT-1: 'ACCEPT',
    -NF_DROP-1: 'DROP',
    -NF_QUEUE-1: 'QUEUE',
}

xt = xtables.xtables(xtables.NFPROTO_IPV4)


class StdoutWrapper(object):
    # XXX: lock?
    def __enter__(self):
        sys.stdout.flush()
        self.stdout = os.dup(1)
        self.r, self.w = os.pipe()
        os.dup2(self.w, 1)

    def __exit__(self, exc_type, exc_value, traceback):
        self.buf = os.read(self.r, 1024)
        os.close(self.w)
        # Clean up the pipe.
        os.close(self.r)
        # Put the original C stdout back in place.
        os.dup2(self.stdout, 1)
        # Clean up the copy we made.
        os.close(self.stdout)


class ipt_replace(ct.Structure):
    _fields_ = [
        ('name', ct.c_char * XT_TABLE_MAXNAMELEN),
        ('valid_hooks', ct.c_uint),
        ('num_entries', ct.c_uint),
        ('size', ct.c_uint),
        ('hook_entry', ct.c_uint * NF_INET_NUMHOOKS),
        ('underflow', ct.c_uint * NF_INET_NUMHOOKS),
        ('num_counters', ct.c_uint),
        ('counters', ct.POINTER(xtables.xt_counters)), # XXX: ignored pointer
        ('entries', ct.c_ubyte * 0),
    ]


def iter_entries(repl):
    """yields all etries in the replace structure"""
    offset = 0
    while offset < repl.size:
        entry = ct.cast(ct.byref(repl.entries, offset), ct.POINTER(ip4tc.ipt_entry))[0]
        yield offset, entry
        assert entry.next_offset >= ct.sizeof(ip4tc.ipt_entry), 'next: %s' % entry.next_offset
        offset += entry.next_offset


def build_chains(repl):
    """returns chain dict and index:chain mapping
    
    output: (chains, user_chain_index)
    where chains is a OrderedDict of {chainname: (offset, entry)}
    user_chain_index is {offset: chainname}
    """
    chains = OrderedDict()
    user_chain_index = {}
    builtin_chains = list((i, entry) for i, entry in enumerate(repl.hook_entry)
            if (1<<i) & repl.valid_hooks)
    chain = None
    for offset, entry in iter_entries(repl):
        if builtin_chains and builtin_chains[0][1] == offset:
            i, _ = builtin_chains.pop(0)
            chainname = HOOKNAMES[i]
            assert chainname not in chains
            chain = [(offset, entry)]
            chains[chainname] = chain
            continue
        
        target = get_target(entry)
        if target.u.user.name == XT_ERROR_TARGET:
            chainname = ct.cast(target.data, ct.c_char_p).value.decode()
            assert chainname not in chains
            chain = []
            chains[chainname] = chain
        else:
            chain.append((offset, entry))
        user_chain_index[offset] = chainname

    # removing the tail entry which is always "ERROR"
    last_chainname, last_entries = chains.popitem()
    assert not last_entries
    assert last_chainname == 'ERROR'
    return chains, user_chain_index


def iter_matches(entry):
    # base_addr = ct.addressof(entry)
    # addr = ct.addressof(entry.matches)
    # addr = ct.addressof(entry.elems)
    offset = ct.sizeof(entry)
    while offset < entry.target_offset:
        match = ct.cast(ct.byref(entry, offset), ct.POINTER(xtables.xt_entry_match))[0]
        yield match
        offset += match.u.match_size


def get_target(entry):
    assert entry.target_offset < entry.next_offset, 'target_offset: %d, next_offset: %d' % (entry.target_offset, entry.next_offset)
    return ct.cast(ct.byref(entry, entry.target_offset), ct.POINTER(xtables.xt_entry_target))[0]


def _ipv4_addr(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack('I', addr.s_addr))


def ipv4_addr(addr, mask):
    """convert ipv4 address (source/dest) to string repr
    """
    return ipaddress.IPv4Network((_ipv4_addr(addr), _ipv4_addr(mask)))


def ipv4_addr_args(flag, addr, mask, invert):
    if not addr.s_addr and not mask.s_addr:
        return

    if invert:
        yield '!'
    
    yield flag
    yield ipv4_addr(addr, mask).compressed


def iface_args(flag, iface, iface_mask, invert):
    if not iface_mask:
        return

    if invert:
        yield '!'

    yield flag
    ifname = iface.decode()
    if len(iface) == len(iface_mask):
        ifname += '+'
    yield ifname


def proto_args(entry):
    if not entry.ip.proto:
        return

    if entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_PROTO:
        yield '!'

    yield '-p'
    yield ip4tc.Rule.protocols.get(entry.ip.proto, str(entry.ip.proto))



def frag_args(entry):
    if not entry.ip.flags & ip4tc.ipt_ip.IPT_F_FRAG:
        return

    if entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_FRAG:
        yield '!'

    yield '-f'


def match_args(match, entry):
    name = match.u.user.name.decode()
    revision = match.u.user.revision
    pmodule = xt.find_match(name)
    if not pmodule:
        yield '[target module %s not found]' % name
    module = pmodule.contents
    module.tflags = 0
    if module.revision != revision:
        yield '[unsupported revision]'
    yield '-m'
    if module.alias:
        yield module.alias(ct.byref(match)).decode()
    else:
        yield name

    if module.save:
        wrapper = StdoutWrapper()
        with wrapper:
            xt.save(module, entry.ip, ct.byref(match))
        # module.save(ct.byref(entry.ip), ct.byref(match))
        yield wrapper.buf.decode().strip()


def read_target_verdict(target):
    """read standard target (that name is empty)"""
    assert not target.u.user.name
    return ct.cast(target.data, ct.POINTER(ct.c_int))[0]


def target_args(entry, offset, user_chain_index):
    # XXX: find specific revision for target
    target = get_target(entry)
    name = target.u.user.name.decode()
    if name:
        yield '-j'
        pmodule = xt.find_target(name)
        if not pmodule:
            yield '[target module %s not found]' % name
        module = pmodule.contents
        module.tflags = 0
        if module.revision != target.u.user.revision:
            yield '[unsupported revision]'
        
        if module.alias:
            yield module.alias(ct.byref(target))
        else:
            yield name

        if module.save:
            wrapper = StdoutWrapper()
            with wrapper:
                xt.save(module, entry.ip, ct.byref(target))
                # module.save(ct.pointer(entry.ip), target)
            yield wrapper.buf.decode().strip()
            # yield 'Target %s is missing save function' % name
    else:
        verdict = read_target_verdict(target)
        # fallthrough
        if verdict == offset + entry.next_offset:
            return

        if entry.ip.flags & ip4tc.ipt_ip.IPT_F_GOTO:
            yield '-g'
        else:
            yield '-j'

        if verdict < 0:  # standard
            yield STANDARD_VERDICT[verdict]
        else:
            yield user_chain_index[verdict]


def rule_args(chain, entry, offset, user_chain_index):
    yield '-A'
    yield chain
    yield from ipv4_addr_args('-s', entry.ip.src, entry.ip.smsk,
                              entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_SRCIP)
    yield from ipv4_addr_args('-d', entry.ip.dst, entry.ip.dmsk,
                              entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_DSTIP)
    yield from iface_args('-i', entry.ip.iniface, entry.ip.iniface_mask,
                          entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_VIA_IN)
    yield from iface_args('-o', entry.ip.outiface, entry.ip.outiface_mask,
                          entry.ip.invflags & ip4tc.ipt_ip.IPT_INV_VIA_OUT)
    yield from proto_args(entry)
    yield from frag_args(entry)
    for match in iter_matches(entry):
        yield from match_args(match, entry)

    # yield from target_args(entry, offset, user_chain_index)


def copy_entry(entry):
    """a simple copy of the entry, including its matches and target"""
    assert entry.next_offset >= ct.sizeof(entry)
    buf = (ct.c_ubyte * entry.next_offset)()
    ct.memmove(buf, ct.byref(entry), entry.next_offset)
    return ct.cast(buf, ct.POINTER(ip4tc.ipt_entry))[0]


def print_table(repl):
    chains, user_chain_index = build_chains(repl)
    # print chains in the order of appearance
    print('*%s' % repl.name.decode())
    for chainname, entries in chains.items():
        if chainname in HOOKNAMES:
            _, policy_entry = entries[-1]
            verdict = read_target_verdict(get_target(policy_entry))
            print(':%s %s' % (chainname, STANDARD_VERDICT[verdict]))
        else:
            print(':%s -' % chainname)

    # print each of the rules
    for chainname, entries in chains.items():
        if chainname in HOOKNAMES:
            entries = entries[:-1]

        for offset, entry in entries:
            # to pass a copy of the entry as the xtables will try to modify the memory
            print(' '.join(rule_args(chainname, copy_entry(entry), offset, user_chain_index)))

    # A final touch of dignity
    print('COMMIT')


bpf_text = '''
#include <net/sock.h>
#include <linux/netfilter_ipv4/ip_tables.h>  /* for struct ipt_replace and IPT_SO_SET_REPLACE */
struct event_header_t {
    u32     tgid;
    u32     pid;
    u32     uid;
    char    comm[TASK_COMM_LEN];
    /*int     retval;*/
    u32     net_ns_inum;
    int     full_entries; /* either we have recorded full entries or just header */
    u64     timestamp_ns; /* Put this at last to serve as 64bit alignment for later data */
};
#define MAX_DATA_SIZE %(max_data_size)d
#define MAX_ENTRIES_SIZE (MAX_DATA_SIZE - sizeof(struct event_header_t) - sizeof(struct ipt_replace))
#define SLOTS = 16

union event_data_t {
    struct event_header_t header;
    char data[MAX_DATA_SIZE];
};

BPF_PERCPU_ARRAY(event_data, union event_data_t, 1);
BPF_PERF_OUTPUT(iptevents);

int kprobe__nf_setsockopt(struct pt_regs *ctx, 
                          struct sock *sk, u_int8_t pf, int val,
                          char __user *opt, unsigned int len) {
    int err = 0;
    if (!(pf == PF_INET && val == IPT_SO_SET_REPLACE)) {
        return 0;
    }
    u32 idx = 0;
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    struct event_header_t* header = event_data.lookup(&idx);
    if (!header) {
        return 0;
    }
    header->timestamp_ns = bpf_ktime_get_ns();
    header->tgid = __pid_tgid >> 32;
    header->pid = __pid_tgid;
    header->uid = bpf_get_current_uid_gid();
    header->net_ns_inum = 0;
#ifdef CONFIG_NET_NS
    header->net_ns_inum = sk->__sk_common.skc_net.net->ns.inum;
#endif
    header->full_entries = 0;
    bpf_get_current_comm(header->comm, sizeof(header->comm));
    struct ipt_replace * repl = (void *)(header + 1);
    bpf_probe_read_user(repl, sizeof(*repl), opt);
    u32 evsize = sizeof(*header) + sizeof(*repl);
    if(repl->size <= MAX_ENTRIES_SIZE) {
        header->full_entries = 1;
        evsize += repl->size;
        bpf_probe_read_user(repl->entries, repl->size, opt + sizeof(struct ipt_replace));
    }
    iptevents.perf_submit(ctx, header, evsize);
    return 0;
}
'''

def convert_time(first_ts, first_ts_real, timestamp_ns):
    t = 1e-9 * (timestamp_ns - first_ts) + first_ts_real
    return time.gmtime(t)


def search_netns(inum, base_path='/var/run/netns'):
    if not os.path.exists(base_path):
        return None

    for entry in os.listdir(base_path):
        if os.stat(os.path.join(base_path, entry)).st_ino == inum:
            return entry

    return None


def print_event(b, mktime, get_netns, cpu, data, size):
    event = b["iptevents"].event(data)
    print('*' * 20)
    tstr = time.strftime('%Y-%m-%dT%H:%M:%S', mktime(event.timestamp_ns))
    repl = ct.cast(ct.byref(event, ct.sizeof(event)), ct.POINTER(ipt_replace))[0]
    root_net_ns_inum = os.stat('/proc/1/ns/net').st_ino
    print('time tgid pid comm netns table num_entries size')
    if event.net_ns_inum == root_net_ns_inum or not event.net_ns_inum:
        netns = '-'
    else:
        netns = event.net_ns_inum
        netnsname = get_netns(event.net_ns_inum)
        if netnsname:
            netns = '%s(%s)' % (netnsname, event.net_ns_inum)
    print('%s %d %d %s %s %s %s %s' % (tstr, event.tgid, event.pid, event.comm.decode(),
                                 netns,
                                 repl.name.decode(), repl.num_entries, repl.size))
    if event.full_entries:
        print_table(repl)


def main():
    # to go beyond this max size, a different delivery mechanism is needed,
    # as percpu array has this size limit
    max_data_size = 32768
    bpfsrc_settings = {
        'max_data_size': max_data_size
    }
    # 5 tables in total, 16 times should be able to cover at least 3 full changes
    page_cnt = int(max_data_size / 4096 * 32)
    try:
        b = BPF(text=bpf_text % bpfsrc_settings)
    except Exception as e:
        raise
    first_ts = BPF.monotonic_time()
    first_ts_real = time.time()
    b["iptevents"].open_perf_buffer(
        partial(print_event, b, partial(convert_time, first_ts, first_ts_real), search_netns),
        page_cnt=page_cnt)
    print('ready')
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == '__main__':
    main()

