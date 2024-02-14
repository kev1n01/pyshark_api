from fastapi import FastAPI
import pyshark as ps
import asyncio
from concurrent.futures import ProcessPoolExecutor

app = FastAPI()

def capture_packets():
    interface_name = r'\Device\NPF_{677625FE-C656-49A2-B2DD-5B42DE0DB497}'
    capture = ps.LiveCapture(interface=interface_name)
    capture.sniff(packet_count=100)

    pkts = []
    for pkt in capture:
        pkts.append({
            'proto': pkt.transport_layer,
            'layer_eth': {
                'source': pkt.eth.src,
                'destination': pkt.eth.dst,
                'type': pkt.eth.type
            },
            'layer_ip': {
                'version': pkt.ip.version,
                'source': pkt.ip.src,
                'destination': pkt.ip.dst,
                'length': pkt.ip.len
            },
            'layer_udp': {
               
            },
            'layer_dns': {
                
            }
        })
        if 'UDP' in pkt:
            pkts[-1]['layer_udp']['checksum'] = pkt.udp.checksum
            pkts[-1]['layer_udp']['source'] = pkt.udp.srcport
            pkts[-1]['layer_udp']['destination'] = pkt.udp.dstport
            pkts[-1]['layer_udp']['length'] = pkt.udp.length

        if 'DNS' in pkt:
            pkts[-1]['layer_dns']['name'] = pkt.dns.qry_name
            pkts[-1]['layer_dns']['flags'] = pkt.dns.flags

    return pkts

async def async_capture_packets():
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, capture_packets)
    return result

@app.get("/v1/capture/")
async def capture_traffic_network():
    pkts = await async_capture_packets()
    return pkts
