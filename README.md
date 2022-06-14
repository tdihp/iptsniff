iptsniff -- sniffing iptables requests
========

This is a bcc based script that shows which process applied what iptables rules.

It taps to all setsockopt calls which can be similar to below bcc trace command:

```
python3 trace.py 'nf_setsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt, unsigned int len), "%d, %d, %d", pf, val, len'
```

Requirements
========

* [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
* [python-iptables](https://github.com/ldx/python-iptables#installing-via-pip)
* libxtables-dev
