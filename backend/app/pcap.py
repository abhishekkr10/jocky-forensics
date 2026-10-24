"""Bounded classic PCAP metadata import. Captured packets are never transmitted."""
import ipaddress
import struct
from datetime import datetime, timezone

def packets(data):
    if len(data)>1048576 or len(data)<24: raise ValueError("PCAP must be 24 bytes to 1 MiB")
    formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if data[:4] not in formats: raise ValueError("Only classic PCAP is supported; convert PCAPNG first")
    endian,precision=formats[data[:4]]
    major,minor,_,_,snaplen,link=struct.unpack(endian+'HHIIII',data[4:24])
    if (major,minor)!=(2,4) or link!=1 or not 0<snaplen<=1048576: raise ValueError("Expected PCAP 2.4 Ethernet capture")
    offset=24
    rows=[]
    while offset<len(data):
        if len(rows)>=1000: raise ValueError("PCAP exceeds 1000 packet limit")
        if offset+16>len(data): raise ValueError("Truncated PCAP packet header")
        seconds,fraction,length,original=struct.unpack(endian+'IIII',data[offset:offset+16]);offset+=16
        if fraction>=precision or length>snaplen or length>original or offset+length>len(data): raise ValueError("Invalid PCAP packet bounds")
        packet=data[offset:offset+length];offset+=length
        timestamp=datetime.fromtimestamp(seconds,tz=timezone.utc).replace(microsecond=fraction*1000000//precision).isoformat()
        row={"event_time":timestamp,"event_kind":"packet_capture","product":"network","captured_bytes":length,"original_bytes":original,"packet_index":len(rows),"timestamp_precision":"nanoseconds" if precision==1000000000 else "microseconds","timestamp_fraction":fraction,"summary":"Captured Ethernet packet"}
        if len(packet)>=14:
            ethertype=int.from_bytes(packet[12:14],'big');start=14
            if ethertype==0x8100 and len(packet)>=18: ethertype=int.from_bytes(packet[16:18],'big');start=18
            payload=packet[start:]
            transport=None
            if ethertype==0x0800 and len(payload)>=20 and payload[0]>>4==4:
                header=(payload[0]&15)*4
                total=int.from_bytes(payload[2:4],'big')
                if header>=20 and header<=len(payload) and total>=header:
                    row.update(source=str(ipaddress.ip_address(payload[12:16])),destination=str(ipaddress.ip_address(payload[16:20])),ip_version=4)
                    protocol=payload[9]
                    if int.from_bytes(payload[6:8],'big')&0x1fff==0: transport=payload[header:min(total,len(payload))]
            elif ethertype==0x86dd and len(payload)>=40 and payload[0]>>4==6:
                row.update(source=str(ipaddress.ip_address(payload[8:24])),destination=str(ipaddress.ip_address(payload[24:40])),ip_version=6)
                protocol=payload[6];transport=payload[40:40+int.from_bytes(payload[4:6],'big')]
            if "ip_version" in row:
                row["protocol"]={6:"tcp",17:"udp"}.get(protocol,f"ip-{protocol}")
                if transport is not None and protocol in {6,17} and len(transport)>=4:
                    row["source_port"],row["port"]=struct.unpack('!HH',transport[:4])
                row["summary"]=f"Captured {row['protocol']} {row['source']} → {row['destination']}"
        rows.append(row)
    return rows
