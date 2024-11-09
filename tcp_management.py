from tcp_connection import tcp_connection

class tcp_manager:

    #initialize the manager for checking the multiple tcp connections
    def __init__(self):
        self.connections = []
        self.general_count = 0
        self.count = 0
        self.established = 0

    #check if the connection are on the same path between the same source and destination address and port
    def track_connection(self, src_ip, src_port, dst_ip, dst_port, seq, ack, flags, timestamp, payload, window):

        connect = self.if_connected(src_ip, src_port, dst_ip, dst_port, timestamp)

        if connect is None:

            connect = tcp_connection(src_ip, src_port, dst_ip, dst_port, timestamp, payload)
            self.connections.append(connect)
            self.count += 1
            connect.num = self.count
            if flags['SYN'] != 1 or (flags['SYN'] == 1 and flags['ACK'] == 1):
                self.established += 1

        self.general_count += 1
        if flags['FIN'] == 1:
            connect.timestamplist.append(timestamp)
            connect.finlist.append(connect.count)

        if flags['RST'] == 1:
            connect.rstlist.append(connect.count)

        connect.seqlist.append(seq)
        connect.acklist.append(ack)

        direction = self.determine_dir(connect, src_ip, src_port, seq, ack)

        connect.flags_updating(flags, seq)
        connect.windows_count(window)

        connect.packets_calculating(direction, seq, ack, timestamp, payload, flags)


    # if the connection has the same address and port as the connection before, it would be count as a part of that connection
    def if_connected(self, src_ip, src_port, dst_ip, dst_port, timestamp):

        for conn in self.connections:
            if (conn.src_addr == src_ip and conn.srcpo == src_port and conn.dst_addr == dst_ip and conn.dstpo == dst_port) or \
               (conn.src_addr == dst_ip and conn.srcpo == dst_port and conn.dst_addr == src_ip and conn.dstpo == src_port):
                conn.count += 1
                return conn
        return None

    def determine_dir(self, conn, src_ip, src_port, seq, ack):

        if src_ip == conn.src_addr and src_port == conn.srcpo:

            return 'src_to_dst'
        else:

            return 'dst_to_src'

    def summary_connections(self):

        total_connection = self.count
        total_all = self.general_count
        complet_conn = 0
        reset_conn = 0
        incomplete_conn = 0
        total_dul = 0
        rtt_value = []
        open_conn = 0
        duration_list = []
        conn_packets = []
        window_list = []
        winsum = []
        count = 0

        print("Summary of TCP connection cap: ")
        print("")
        print("A) Total number of connections: ", total_connection)
        print("------------------------------------------")
        print("B) Connection details: ")
        print("")
        for conn in self.connections:
            summary = conn.summary()
            count += 1
            print("Connection", str(count)+":")
            print("Source address:", summary['src_ip'])
            print("Destination address:", summary['dst_ip'])
            print("Source port:", summary['src_port'])
            print("Destination port:", summary['dst_port'])



            if summary['fin_count'] >= 1 and summary['syn_count'] >= 1:
                complet_conn += 1

                print("Status:", summary['connectionstatus'])
                conn_len = len(conn.timestamplist)
                end_time = conn.timestamplist[conn_len-1]
                conn.connection_end(end_time)

                print("Start time:", summary['start_time'], "seconds")
                print("End time:", end_time, "seconds")

                print("Duration:", round(end_time-summary['start_time'], 6), "seconds")

                print("Number of packets sent from Source to Destination:", summary['packets_src_to_dst'])
                print("Number of packets sent from Destination to Source:", summary['packets_dst_to_src'])
                print("Total number of packets:", conn.count)
                print("Number of data bytes sent from Source to Destination:", summary['bytes_src_to_dst'])
                print("Number of data bytes sent from Destination to Source:", summary['bytes_dst_to_src'])
                print("Total number of data bytes:", summary['total_bytes'])

                print("END")

                print("+++++++++++++++++++++++++++++++++++++++++")

                duration = end_time - summary['start_time']
                duration_list.append(duration)
                for element in summary['rtt_value']:
                     rtt_value.append(round(element, 6))
                conn_packets.append(summary['packet_num'])
                for win in summary['windows']:
                     window_list.append(win)

                winsum.append(summary['avg_win'])

            else:
                incomplete_conn += 1

                print("Status:", summary['connectionstatus'])
                print("++++++++++++++++++++++++++++++++++++++++++")

            if summary['rstnum']>=1:
                reset_conn += 1

            if summary['status'] == "open":
                open_conn += 1

        print("C) General: ")
        print("")
        print("The total number of complete TCP connections:", complet_conn)
        print("The number of reset TCP connections:", reset_conn)
        print("The number of TCP connections that were still open when the trace capture ended:", open_conn)
        print("The number of TCP connections established before the capture started:", self.established)

        print("----------------------------------------------------------")


        return duration_list, rtt_value, conn_packets, window_list
