from bcc import BPF
import time
device = "lo"
b = BPF(src_file="filter.c")
fn = b.load_func("udpfilter", BPF.XDP)
b.attach_xdp(device, fn, 0)
print("Starting the filter ...")
try:
  b.trace_print()
except KeyboardInterrupt:
  pass
b.remove_xdp(device, 0)