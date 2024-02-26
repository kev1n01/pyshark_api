from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pyshark as ps
import asyncio
from concurrent.futures import ProcessPoolExecutor

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite solicitudes desde cualquier origen
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos HTTP
    allow_headers=["*"],  # Permite todos los encabezados
)

def capture_packets():
    interface_name_wifi = r'\Device\NPF_{677625FE-C656-49A2-B2DD-5B42DE0DB497}' #interfaz de red wifi comando: tshark -D
    interface_name_ethernet= r'\Device\NPF_{37440D2E-8411-41CB-830E-D731C44B496A}' #interfaz de red ethernet comando: tshark -D
    capture = ps.LiveCapture(interface=interface_name_wifi)
    capture.sniff(packet_count=100)

    pkts = []
    for pkt in capture:
        pkts.append({
            'proto': pkt.transport_layer,
            'layer_eth': {
            },
            'layer_ip': {
            },
            'layer_udp': {
            },
            'layer_dns': {
            }
        })
        if 'ETH' in pkt:
            pkts[-1]['layer_eth']['source'] = pkt.eth.src
            pkts[-1]['layer_eth']['destination'] = pkt.eth.dst
            pkts[-1]['layer_eth']['type'] = pkt.eth.type
        
        if 'IP' in pkt:
            pkts[-1]['layer_ip']['version'] = pkt.ip.version
            pkts[-1]['layer_ip']['source'] = pkt.ip.src
            pkts[-1]['layer_ip']['destination'] = pkt.ip.dst
            pkts[-1]['layer_ip']['length'] = pkt.ip.len
        
        if 'UDP' in pkt:
            pkts[-1]['layer_udp']['checksum'] = pkt.udp.checksum
            pkts[-1]['layer_udp']['source'] = pkt.udp.srcport
            pkts[-1]['layer_udp']['destination'] = pkt.udp.dstport
            pkts[-1]['layer_udp']['length'] = pkt.udp.length

        if 'DNS' in pkt:
            pkts[-1]['layer_dns']['name'] = pkt.dns.qry_name
            pkts[-1]['layer_dns']['flags'] = pkt.dns.flags
            pkts[-1]['layer_dns']['type'] =  pkt.dns.qry_type 

    return pkts

def capture_packets_deploy():
    capture = ps.LiveCapture(interface='eth0')
    capture.sniff(packet_count=100)

    pkts = []
    for pkt in capture:
        pkt.append({
            'proto': 'algo random',
            'layer_eth': {
            },
            'layer_ip': {
            },
            'layer_udp': {
            },
            'layer_dns': {
            }
        })

    return pkts
    

async def async_capture_packets():
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, capture_packets)
    return result

async def async_capture_packets_deploy():
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, capture_packets_deploy)
    return result

@app.get("/")
async def capture_traffic_network_local():
    pkts = await async_capture_packets()
    return pkts

@app.get("/eth")
async def capture_traffic_network_deploy():
    pkts = await async_capture_packets_deploy()
    return pkts