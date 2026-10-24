import struct
import pytest
from backend.app.pcap import packets

def capture():
    ethernet=b'\0'*12+b'\x08\x00'
    ip=bytes.fromhex('4500001c0000000040110000c000020acb007119')
    udp=struct.pack('!HHHH',1234,443,8,0)
    packet=ethernet+ip+udp
    return bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,1)+struct.pack('<IIII',1700000000,123456,len(packet),len(packet))+packet

def test_packet_metadata_and_timestamp():
    row=packets(capture())[0]
    assert row['source']=='192.0.2.10'
    assert row['destination']=='203.0.113.25'
    assert row['protocol']=='udp'
    assert row['port']==443
    assert row['event_time']=='2023-11-14T22:13:20.123456+00:00'

def test_rejects_truncated_and_wrong_formats():
    for bad in [capture()[:-1],b'\0'*24,capture()[:30]]:
        with pytest.raises(ValueError): packets(bad)

def test_capture_import_is_network_evidence(tmp_path,monkeypatch):
    from backend.app import engine
    (tmp_path/'fixtures').mkdir()
    (tmp_path/'fixtures'/'capture.pcap').write_bytes(capture())
    monkeypatch.setattr(engine,'ROOT',tmp_path)
    bundle=engine.run('mode live\ntarget host\nimport pcap "capture.pcap" as packets\nverify evidence',"capture-test","capture-case")
    record=engine.records(bundle)[0]
    assert record['artifact_type']=='network_connections'
    assert record['provenance_kind']=='imported'
    assert record['collector_id']=='pcap'
    assert record['payload']['port']==443
