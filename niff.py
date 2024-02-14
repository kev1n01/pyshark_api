import pyshark as ps
def print_packet_summary(pkt):
    # print("    ", str(pkt)[:120])
    print(pkt)

interface_name = r'\Device\NPF_{677625FE-C656-49A2-B2DD-5B42DE0DB497}'
capture = ps.LiveCapture(interface=interface_name,  bpf_filter='udp port 53')
capture.sniff(packet_count=50)
for pkt in capture:
    print_packet_summary(pkt)