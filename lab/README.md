# lab/

Demo + DX1 scenarios on kind with NGF (TR-06, TR-23).

## Environment gates

- `verify-xdp-chain.sh` — proves the Linux host can compile CO-RE eBPF,
  verify-load, pin, attach XDP and detach cleanly (TR-03). Run with sudo
  on a Linux host; output is pasted into kernel-side PR bodies.
