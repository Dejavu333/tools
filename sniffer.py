import socket
import struct
import argparse
import platform

def parse_arguments():
    """
    Parse command-line arguments for the packet sniffer.
    
    Returns:
        Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('--bind_ip', type=str, required=True, 
                        help='IP address to bind the sniffer to (e.g., 192.168.0.10)')
    parser.add_argument('--src_ip', type=str, 
                        help='Filter packets by source IP address')
    parser.add_argument('--dest_ip', type=str, 
                        help='Filter packets by destination IP address')
    parser.add_argument('--src_port', type=int, 
                        help='Filter packets by source port number')
    parser.add_argument('--dest_port', type=int, 
                        help='Filter packets by destination port number')
    parser.add_argument('--protocol', type=int, choices=[1, 6], 
                        help='Filter packets by protocol (1 for ICMP, 6 for TCP)')
    parser.add_argument('--showdata', action='store_true', 
                        help='Display the data inside the packet')
    return parser.parse_args()

def sniff_packets(bind_ip, src_ip_filter=None, dest_ip_filter=None, 
                  src_port_filter=None, dest_port_filter=None, 
                  protocol_filter=None, show_data=False):
    """
    Sniff packets on the specified network interface.
    
    Args:
        bind_ip (str): IP address to bind the sniffer to. 
                       This allows you to specify which network interface the sniffer will listen on.
        src_ip_filter (str): Optional; Source IP address to filter packets.
        dest_ip_filter (str): Optional; Destination IP address to filter packets.
        src_port_filter (int): Optional; Source port number to filter packets.
        dest_port_filter (int): Optional; Destination port number to filter packets.
        protocol_filter (int): Optional; Protocol number to filter. 
                               Accepts 1 for ICMP and 6 for TCP packets.
        show_data (bool): If True, display the raw data contained within the packet. 
                          This can be useful for debugging or analysis of the payload.
    """
    # Create a raw socket. The socket type and protocol depend on the operating system.
    if platform.system() == "Windows":
        # Create a raw socket for Windows
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((bind_ip, 0))  # Bind the socket to the specified IP address and any port (0)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers in the packet
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode to capture all packets
    else:
        # Create a raw socket for Linux/Unix
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    try:
        while True:
            # Receive packets. The maximum size of packets we can capture is 65565 bytes.
            packet = sock.recvfrom(65565)[0]

            # Extract the first 20 bytes for the IP header.
            ip_header = packet[0:20]
            # Unpack the IP header using the specified format.
            # The format string '!BBHHHBBH4s4s' specifies how to interpret the byte data:
            #   !: Network byte order (big-endian)
            #   B: Unsigned char (1 byte) - Version and IHL
            #   B: Unsigned char (1 byte) - Type of Service (ToS)
            #   H: Unsigned short (2 bytes) - Total Length
            #   H: Unsigned short (2 bytes) - Identification
            #   H: Unsigned short (2 bytes) - Flags and Fragment Offset
            #   B: Unsigned char (1 byte) - Time to Live (TTL)
            #   B: Unsigned char (1 byte) - Protocol (1 for ICMP, 6 for TCP)
            #   H: Unsigned short (2 bytes) - Header Checksum
            #   4s: 4-byte string - Source IP address
            #   4s: 4-byte string - Destination IP address
            ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # Extract version and Internet Header Length (IHL)
            version_ihl = ip_fields[0]  # First byte contains version and IHL
            ihl = version_ihl & 0xF  # Use bitwise AND with 0xF (binary 1111) to get the IHL
            version = version_ihl >> 4  # Shift right by 4 bits to get the version number (IPv4)

            # Total Length of the packet (header + data) is in the third field
            total_length = ip_fields[2]
            protocol = ip_fields[6]  # Protocol field indicates the higher-layer protocol used
            source_ip = socket.inet_ntoa(ip_fields[8])  # Convert source IP from bytes to string
            dest_ip = socket.inet_ntoa(ip_fields[9])  # Convert destination IP from bytes to string

            # Apply IP filters if specified
            if (src_ip_filter and src_ip_filter != source_ip) or \
               (dest_ip_filter and dest_ip_filter != dest_ip):
                continue  # Skip packet if it doesn't match the IP filters

            # Apply protocol filter if specified
            if protocol_filter and protocol_filter != protocol:
                continue  # Skip packet if it doesn't match the protocol filter

           # Print IP header details, providing a clear overview of the packet's IP information
            print(f'Version: {version:<5} '
                f'IHL: {ihl:<5} '
                f'Total Length: {total_length:<10} '
                f'Protocol: {protocol:<5} '
                f'Source IP: {source_ip:<16} '
                f'Destination IP: {dest_ip:<16}')
            
            # Process TCP packets (protocol number 6)
            if protocol == 6:  # Check if protocol is TCP
                tcp_header = packet[ihl * 4:ihl * 4 + 20]  # TCP header starts after the IP header
                # Unpack the TCP header to extract relevant fields:
                #   HH: Source and Destination Ports (2 bytes each)
                #   LL: Sequence and Acknowledgment Numbers (4 bytes each)
                #   BB: Data Offset and Reserved + Flags (1 byte each)
                #   HH: Window Size (2 bytes)
                #   H: Checksum (2 bytes)
                #   H: Urgent Pointer (2 bytes)
                tcp_fields = struct.unpack('!HHLLBBHHH', tcp_header)
                source_port = tcp_fields[0]  # Source port number
                dest_port = tcp_fields[1]  # Destination port number

                # Apply port filters if specified
                # todo filtering must not be here
                if (src_port_filter and src_port_filter != source_port) or \
                   (dest_port_filter and dest_port_filter != dest_port):
                    continue  # Skip packet if it doesn't match port filters

                print(f'\tTCP: Source Port: {source_port:<10} Destination Port: {dest_port}')

            # Process ICMP packets (protocol number 1)
            elif protocol == 1:  # Check if protocol is ICMP
                icmp_header = packet[ihl * 4:ihl * 4 + 8]  # ICMP header starts immediately after the IP header
                # Unpack the ICMP header:
                #   B: Type (1 byte)
                #   B: Code (1 byte)
                #   HH: Checksum (2 bytes)
                #   H: Identifier (2 bytes)
                #   H: Sequence Number (2 bytes)
                icmp_fields = struct.unpack('!BBHHH', icmp_header)
                icmp_type = icmp_fields[0]  # ICMP type (e.g., Echo Request)
                icmp_code = icmp_fields[1]  # ICMP code (subtype)
                print(f'\tICMP: Type: {icmp_type:<10}, Code: {icmp_code:<10}')

            # Show packet data if requested by the user
            if show_data:
                # Determine where the data begins based on the protocol
                # For TCP, data starts after the TCP header; for ICMP, it starts after the ICMP header.
                data = packet[ihl * 4 + (20 if protocol == 6 else 8):]  # 20 bytes for TCP header, 8 bytes for ICMP
                # Convert the raw data to ASCII, ignoring non-printable characters
                ascii_data = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
                print(f'\tData: {ascii_data}')  # Print the ASCII representation of the data

    except KeyboardInterrupt:
        print("Sniffer stopped.")  # Gracefully handle a keyboard interrupt to stop the sniffer
    finally:
        sock.close()  # Ensure the socket is closed upon exit

if __name__ == "__main__":
    # Parse command-line arguments to configure the packet sniffer
    args = parse_arguments()
    # Start the packet sniffing process with the specified parameters
    sniff_packets(bind_ip=args.bind_ip, 
                  src_ip_filter=args.src_ip, 
                  dest_ip_filter=args.dest_ip, 
                  src_port_filter=args.src_port, 
                  dest_port_filter=args.dest_port, 
                  protocol_filter=args.protocol, 
                  show_data=args.showdata)
