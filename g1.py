import pyshark


def find_zip_file(pcap_path):
    try:
        cap = pyshark.FileCapture(pcap_path)
        for packet in cap:
            if "TCP" in packet:
                try:
                    tcp_payload = bytes.fromhex(packet.tcp.payload.replace(":", ""))
                    if tcp_payload.startswith(b"PK"):
                        print(f"Possible ZIP file found in packet {packet.number}")
                        with open("extracted.zip", "wb") as out:
                            out.write(tcp_payload)
                        print("ZIP file saved as 'extracted.zip'")
                        return
                except Exception as e:
                    continue
        print("No ZIP file found.")
    except Exception as e:
        print(f"Error processing PCAP file: {e}")


if __name__ == "__main__":
    find_zip_file("traffic.pcap")
