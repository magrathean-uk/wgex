# Capture

The verdict driver starts guarded guest captures on en0 and the lab utun with snaplen 256. IPERF3 skips captures to avoid distorting throughput and records the omission. Completed files are stored beneath build_root()/lab-captures/ROW/NONCE. It reads en0 pcaps with host `tcpdump -r`, never a host live capture or BPF handle, and checks marked port-53/IPv6 traffic with exact nonce-label matching. Captured rows require a positive unprotected system-resolver query in the capture. Legacy `just lab pcaps` fetches into lab-captures/manual and tolerates a missing stop helper.
