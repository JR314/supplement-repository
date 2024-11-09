class tcp_connection:

    # initilize the tcp class for the other code file
    def __init__(self, src_ip, src_port, dst_ip, dst_port, timetamp, payload):

        self.src_addr = src_ip
        self.srcpo = src_port
        self.dst_addr = dst_ip
        self.dstpo = dst_port
        self.start = timetamp
        self.end = timetamp
        self.stdsum = 0
        self.dtssum = 0
        self.stdbytes = 0
        self.dtsbytes = 0
        self.syn = 0
        self.fin = 0
        self.rstnum = 0
        self.rststatus = ""
        self.rst = False
        self.rtt_value = []
        self.count = 1
        self.timestamplist = []
        self.seqlist = []
        self.finlist = []
        self.acklist = []
        self.status = "open"
        self.seqack = {}
        self.ackcount = {}
        self.windows = []
        self.stdtime = {}
        self.dtstime = {}
        self.seq = []
        self.ack = []
        self.stdfirstseq = 0
        self.dtsfirstseq = 0
        self.stdcount = 0
        self.dtscount = 0
        self.stdfirstack = 0
        self.dtsfirstack = 0
        self.rstlist = []
        self.num = 0


    def flags_updating(self, flags, seq):

        if flags['SYN'] == 1:
            self.syn += 1
            self.status = "open"

        if flags['FIN'] == 1:
            self.fin += 1
            self.status = "close"
        if flags['RST'] == 1:
            self.rst = True
            self.rstnum += 1
            self.rststatus = "/R"


    def windows_count(self, window):

        self.windows.append(window)


    def connection_end(self, end_time):
        #self.end = end_time
        self.end = end_time


    def packets_calculating(self, direction, seq, ack, timestamp, payload, flags):

        if direction == 'src_to_dst':
            self.stdsum += 1
            self.stdbytes += payload

            self.seq.append(seq)
            self.ack.append(ack)

            if flags['SYN'] == 1 or flags['FIN'] == 1:

                    self.stdtime[seq+1] = timestamp

            elif ack not in self.dtstime:


                if flags['RST'] == 0:
                    if flags['ACK'] == 1 and flags['PSH'] == 0 and flags['SYN'] == 0 and flags['FIN'] == 0:

                         self.stdtime[seq+payload] = timestamp



        elif direction == 'dst_to_src':
            self.dtssum += 1
            self.dtsbytes += payload

            self.seq.append(seq)
            self.ack.append(ack)
            if flags['SYN'] == 1 or flags['FIN'] == 1:
                self.dtstime[seq+1] = timestamp
            else:
                self.dtstime[seq+payload] = timestamp

            if ack in self.stdtime:

                rtt = timestamp - self.stdtime[ack]
                self.rtt_value.append(rtt)
                del self.stdtime[ack]


    #summary of the connection between the two hosts
    def summary(self):

        rtt_minimum = None
        rtt_maximum = None
        rtt_average = None

        duration = None

        if self.end:
            duration = self.end - self.start

        status_of = "S" + str(self.syn) + "F" + str(self.fin) + self.rststatus

        count = 0
        lenfinlist = len(self.finlist)
        lastfin = 0
        if lenfinlist != 0:
            lastfin = self.finlist[lenfinlist-1]
            if lastfin == self.count:
                self.status = 'close'
            else:
                if self.acklist[lastfin] == self.seqlist[lastfin-1] + 1:
                      self.status = 'close'
                else:
                      self.status = 'open'
                      if self.rst == True:
                          if len(self.rstlist) != 0:
                              if self.rstlist[len(self.rstlist)-1] > lastfin:
                                  self.status = 'close'

        avg_win = sum(self.windows)/len(self.windows)


        summary_list = {'src_ip': self.src_addr, 'src_port': self.srcpo, 'dst_ip': self.dst_addr,
            'dst_port': self.dstpo,
            'start_time': self.start,
            'end_time': self.end,
            'duration': duration,
            'packets_src_to_dst': self.stdsum,
            'packets_dst_to_src': self.dtssum,
            'bytes_src_to_dst': self.stdbytes,
            'bytes_dst_to_src': self.dtsbytes,
            'total_bytes': self.stdbytes + self.dtsbytes,
            'syn_count': self.syn,
            'fin_count': self.fin,
            'rst': self.rst,
            'rstnum': self.rstnum,
            'status': self.status,
            'connectionstatus': status_of,
            'rtt_value': self.rtt_value,
            'packet_num': self.count,
            'windows': self.windows,
            'avg_win': avg_win,
            'seq': self.seq,
            'ack': self.ack
            }

        return summary_list
