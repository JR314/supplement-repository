import sys
from struct import *
from packet_struct import packet
from tcp_management import tcp_manager
import struct

def parse_cap(filename, manager):

    with open(filename, 'rb') as f:
        global_header = f.read(24)
        
        count = 0
        ordering = ""

        magic_number = global_header[0:4]
        if magic_number == b'\xd4\xc3\xb2\xa1':
            ordering = "<"
        elif magic_number == b'\xa1\xb2\xc3\xd4':
            ordering = ">"

        version_major = struct.unpack(ordering+"H", global_header[4:6])[0]
        version_minor = struct.unpack(ordering+"H", global_header[6:8])[0]
        thiszone = struct.unpack(ordering + "I", global_header[8:12])[0]
        sigfigs = struct.unpack(ordering + "I", global_header[12:16])[0]
        snaplen = struct.unpack(ordering + "I", global_header[16:20])[0]
        network = struct.unpack(ordering + "I", global_header[20:])[0]

        while True:
            packet_header = f.read(16)
            if not packet_header:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ordering+'IIII', packet_header)

            packet_data = f.read(incl_len)


            packet, payload, window, protocol = parse_packet_data(packet_data, incl_len)
            timestamp = ts_sec + ts_usec / 1000000.0

            if count == 0:
                initial = timestamp


            if protocol == 6:
                manager.track_connection(
                    packet.IP_header.src_ip, packet.TCP_header.src_port,
                    packet.IP_header.dst_ip, packet.TCP_header.dst_port,
                    packet.TCP_header.seq_num, packet.TCP_header.ack_num,
                    packet.TCP_header.flags, round(timestamp-initial, 6), payload, window
                )
                count += 1


    return 0

def parse_packet_data(data, incl_len):

    eth_header_len = 14
    eth_header = data[:eth_header_len]

    packt = packet()

    ip_header_offset = eth_header_len

    ip_header_len = (data[ip_header_offset] & 0x0F) * 4
    total_ip_length = struct.unpack('!H', data[ip_header_offset+2:ip_header_offset+4])[0]

    ip_header = data[ip_header_offset:ip_header_offset + 20]  # IP header is 20 bytes
    protocol = struct.unpack("!B", ip_header[9:10])[0]

    # Extract the IHL field to find out how long the IP header is
    ihl = ip_header[0] & 0x0F  # Lower 4 bits of the first byte
    ip_header_len = ihl * 4  # IHL is in 4-byte blocks

    # TCP/UDP Header
    tcp_header_offset = ip_header_offset + ip_header_len
    tcp_header = data[tcp_header_offset:tcp_header_offset + 20]  # First 20 bytes of TCP header

    # Extract the Data Offset field from the TCP header to find out how long it is
    data_offset = (tcp_header[12] >> 4) & 0x0F # Upper 4 bits of the 13th byte
    #data_offset = tcp_header[12] & 0xF0
    tcp_header_len = data_offset * 4  # Data offset is in 4-byte blocks

    # The payload starts after the TCP header

    payload = total_ip_length - ip_header_len - tcp_header_len

    src_ip = ip_header[12:16]  # Source IP address
    dst_ip = ip_header[16:20]  # Destination IP address



    packt.IP_header.get_IP(src_ip, dst_ip)


    packt.TCP_header.get_src_port(data[tcp_header_offset:tcp_header_offset+2])
    packt.TCP_header.get_dst_port(data[tcp_header_offset+2:tcp_header_offset+4])
    packt.TCP_header.get_seq_num(data[tcp_header_offset+4:tcp_header_offset+8])
    packt.TCP_header.get_ack_num(data[tcp_header_offset+8:tcp_header_offset+12])
    packt.TCP_header.get_flags(data[tcp_header_offset+13:tcp_header_offset+14])

    window_size_offset = tcp_header_offset + 14
    window_size = struct.unpack('!H', data[window_size_offset:window_size_offset + 2])[0]

    return packt, payload, window_size, protocol



def main():

    try:
        capfile = sys.argv[1]
    except:
        print("Input file error")
        exit(0)

    try:
        manager = tcp_manager()
        parse_cap(capfile, manager)
    except:
        print("processing error")
        exit(0)

    duration_list, rtt_value, conn_packets, window_list = manager.summary_connections()

    if duration_list == []:
        duration_list.append(0)
    if rtt_value == []:
        rtt_value.append(0)
    if conn_packets == []:
        conn_packets.append(0)
    if window_list == []:
        window_list.append(0)

    print("D) Complete TCP connections:")
    print("")
    print("Minimum time duration:", round(min(duration_list), 6), "seconds")
    print("Mean time duration:", round(sum(duration_list)/len(duration_list), 6), "seconds")
    print("Maximum time duration:", max(duration_list), "seconds")
    print("")
    print("Minimum RTT value:", min(rtt_value))
    print("Mean RTT value:", round(sum(rtt_value)/len(rtt_value), 6))
    print("Maximum RTT value:", max(rtt_value))
    print("")
    print("Minimum number of packets including both send/received:", min(conn_packets))
    print("Mean number of packets including both send/received:", sum(conn_packets)/len(conn_packets))
    print("Maximum number of packets including both send/received:", max(conn_packets))
    print("")
    print("Minimum receive window size including both send/received:", min(window_list), "bytes")
    print("Mean receive window size including both send/received:", round(sum(window_list)/len(window_list), 6), "bytes")
    print("Maximum receive window size including both send/received:", max(window_list), "bytes")



if __name__ == "__main__":
    main()
