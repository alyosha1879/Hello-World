print "Hello,world."


class DHCP_HANDLER():

    def __init__(self, datapath, in_port, pkt_dhcp):

        self.datapath = datapath
        self.in_port = in_port
        self.pkt_dhcp = pkt_dhcp

        # DHCPのオペレーションコード
        self.op = pkt_dhcp.op
        self.htype = pkt_dhcp.htype
        # フラグ
        self.flags = pkt_dhcp.flags
        # DHCPのID
        self.xid = pkt_dhcp.xid
        # クライアントIPアドレス
        self.ciaddr = pkt_dhcp.ciaddr
        #　DHCPサーバが割り当てるクライアントのIPアドレス
        self.yiaddr = pkt_dhcp.yiaddr
        #　DHCPサーバのIPアドレス
        self.siaddr = pkt_dhcp.siaddr
        #　DHCPリレーエージェントのIPアドレス
        self.giaddr = pkt_dhcp.giaddr
        #　クライアントのMACアドレス
        self.chaddr = pkt_dhcp.chaddr
        self.sname = pkt_dhcp.sname
        self.boot_file = pkt_dhcp.boot_file
        self.options = pkt_dhcp.options       
        # クライアントの所属するISP
        self.ispId = None

        #LOG.debug("op...%s, xid...%s, ciaddr...%s, yiaddr...%s, siaddr...%s, giaddr...%s, chaddr...%s, options...%s", self.op, self.xid, self.ciaddr, self.yiaddr, self.siaddr, self.giaddr, self.chaddr, self.options)

        headOption = self.options.option_list[0]
        #LOG.debug("headOption...%s", headOption)
        msgType = headOption.value

        #LOG.debug("DHCP_TABLE...%s", DHCP_TABLE)

        # DHCPDISCOVER受信時
        if msgType == '\x01':
            #LOG.debug("DHCP DISCOVER RECEIVED.")

            self._send_dhcp_offer()

        # DHCPREQUEST受信時
        if msgType == '\x03':
            self._calc_ip()

            #LOG.debug("DHCP REQUEST RECEIVED.")
            self._send_dhcp_ack()          

    @log_deco
    def _calc_ip(self):

            sql = "select isp_id from vm_info where nic2_mac = \"%s\";" % self.chaddr
            #LOG.debug("sql...%s", sql)
            ispId = send_query("select isp_id from vm_info where nic2_mac = \"%s\";" % self.chaddr)[0][0]
            #LOG.debug("ispId...%s", ispId)

            sql = "select vm_id from vm_info where nic2_mac = \"%s\";" % self.chaddr
            #LOG.debug("sql...%s", sql)
            vmId = send_query("select isp_id from vm_info where nic2_mac = \"%s\";" % self.chaddr)[0][0]
            #LOG.debug("vmId...%s", vmId)

            nwAddr = send_query("select nw_addr from isp_info where isp_id = \"%s\";" % ispId )[0][0]
            #LOG.debug("nwAddr...%s", nwAddr)

            defaultIp = IPNetwork(nwAddr).ip
            #LOG.debug("defaultIP...%s", str(defaultIp))
   
            vmCount = send_query("select count(*) from vm_info where isp_id = %s ;" % ispId)[0][0]
            #LOG.debug("vmCount...%s", vmCount)

            self.ispId = int(ispId)

            gwAddr = str(IPAddress(int(defaultIp) + 1))
            self.new_yiaddr = str(IPAddress(int(defaultIp) + vmCount + 100))
            #LOG.debug("yiaddr...%s", self.yiaddr)
      
            DHCP_TABLE[self.chaddr] = self.new_yiaddr
            DHCP_TABLE[self.xid] = gwAddr

    @log_deco
    def _send_dhcp_ack(self):

        self.new_yiaddr = DHCP_TABLE[self.chaddr]
        gwAddr = DHCP_TABLE[self.xid]

        #LOG.debug("new_yiaddr...%s, gwAddr...%s", self.new_yiaddr, gwAddr)
        
        pkt = packet.Packet()
        # イーサフレーム
        pkt.add_protocol(ethernet.ethernet(dst=self.chaddr, src="00:11:22:33:44:55"))

        # IPヘッダー
        pkt.add_protocol(ipv4.ipv4(src="192.168.1.1", dst="255.255.255.255", proto=17))

        # UDPヘッダー  
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))

        # DHCPメッセージ

        ##LOG.debug("hex(IPAddress(gwAddr))...%s", hex(IPAddress(gwAddr)))
        hexGWAddr = hex(IPAddress(gwAddr))

        msgOption = dhcp.option(tag=53 ,value='\x05')

        # テストの結果、デフォルトGWの設定はackで行う模様
        if self.ispId == 200: 
            gwOption = dhcp.option(tag=3, value='\x0B\x0B\x0B\x01')
        elif self.ispId == 201:
            gwOption = dhcp.option(tag=3, value='\x0C\x0C\x0C\x01')

        idOption = dhcp.option(tag=54, value='\xc0\xa8\x01\x01')
        subnetOption = dhcp.option(tag=1, value='\xFF\xFF\xFF\x00')
        timeOption = dhcp.option(tag=51, value='\xFF\xFF\xFF\xFF')         
        options = dhcp.options(option_list = [msgOption, idOption, timeOption, subnetOption, gwOption])

        pkt.add_protocol(dhcp.dhcp(op=2, chaddr=self.chaddr, yiaddr=self.new_yiaddr, giaddr=self.giaddr, xid=self.xid, hlen=6, options=options))
        send_packet(self.datapath, self.in_port, pkt)

        sql = "update vm_info set NIC2_IP = \"%s\" where nic2_mac = \"%s\";" % (self.new_yiaddr, self.chaddr)
        #LOG.debug("sql...%s", sql)
        send_query(sql)

    @log_deco
    def _send_dhcp_offer(self):

        pkt = packet.Packet()
        # イーサフレーム
        pkt.add_protocol(ethernet.ethernet(dst=self.chaddr, src="00:11:22:33:44:55"))
        # IPヘッダー
        pkt.add_protocol(ipv4.ipv4(src="192.168.1.1", dst="255.255.255.255", proto=17))
        # UDPヘッダー
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        # DHCPメッセージ
        option = dhcp.option(tag=53 ,value='\x02')
        #gwOption = dhcp.option(tag=3, value='\x0B\x0B\x0B\x01')
        options = dhcp.options(option_list = [option])
        pkt.add_protocol(dhcp.dhcp(op=2, chaddr=self.chaddr, yiaddr=self.yiaddr, giaddr=self.giaddr, xid=self.xid, hlen=6, options=options))
        send_packet(self.datapath, self.in_port, pkt)
