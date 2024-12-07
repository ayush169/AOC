import pyshark


def analyze_pcap(pcap_file):
    print("Starting analysis...")

    # Open the capture file
    cap = pyshark.FileCapture(pcap_file)

    # Track TCP streams we've seen
    seen_streams = set()

    for packet in cap:
        try:
            if "TCP" in packet:
                stream_index = int(packet.tcp.stream)

                # Only process each stream once
                if stream_index not in seen_streams:
                    seen_streams.add(stream_index)

                    # Try to get raw data if it exists
                    if hasattr(packet, "raw"):
                        raw_data = packet.raw_mode
                        print(f"\nStream {stream_index}:")
                        print(f"Source Port: {packet.tcp.srcport}")
                        print(f"Destination Port: {packet.tcp.dstport}")
                        print(
                            f"Raw data preview: {raw_data[:100] if raw_data else 'No raw data'}"
                        )

                    # Check for HTTP layer
                    if hasattr(packet, "http"):
                        print(f"\nHTTP Data found in stream {stream_index}:")
                        if hasattr(packet.http, "request"):
                            print(f"Request: {packet.http.request}")
                        if hasattr(packet.http, "response"):
                            print(f"Response: {packet.http.response}")

                # If it's a SYN packet (new connection)
                if hasattr(packet.tcp, "flags") and packet.tcp.flags == "2":
                    print(f"\nNew TCP connection detected:")
                    print(f"Stream {stream_index}")
                    print(f"Source Port: {packet.tcp.srcport}")
                    print(f"Destination Port: {packet.tcp.dstport}")

        except AttributeError as e:
            continue
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            continue

    cap.close()
    print("\nAnalysis complete")


if __name__ == "__main__":
    pcap_file = "traffic.pcap"
    analyze_pcap(pcap_file)
