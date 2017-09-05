"""
.. module:: pathspider.chains.traceroute
   :synopsis: A flow analysis chain for traceroute messages especially icmp messages

"""

from pathspider.chains.base import Chain
from pathspider.traceroute_base import INITIAL_SEQ
from pathspider.traceroute_base import INITIAL_PORT
from pip._vendor.progress import counter
import base64

class ECNChain_trace(Chain):

    def box_info(ip):    
        """ECN-specific Destination Stuff"""    
        if ip.tcp:
           
            """ECN-specific stuff like flags and DSCP"""
            ecn = ip.traffic_class
            flags = ip.tcp.data[13]                   
            payload_len = 9  #we don't care but needs to be bigger than 9 for ecn_flags to work properly
                       
            dscp = ecn >> 2                      
              
            [syn, ack] = ECNChain_trace.syn_flags(flags)
              
            """Calculating final hop with sequence number """
            [ece, cwr, ect] = ECNChain_trace.ecn_flags(ecn, flags, payload_len) # !!!!!Why is self.ecn... not working?

            return [ece, cwr, ect, syn, ack, ("DSCP: %u" %dscp)]              
             
        """ECN-specific traceroute Stuff""" 
        if ip.icmp:
                
            """length of payload that comes back to identify RFC1812-compliant routers"""
            pp = ip.icmp.payload.payload
            payload_len = len(pp)
             
            """payload data of returning packet for bitwise comparison in merger""" 
            data = ip.icmp.payload.data
      
            """ECN-specific stuff like flags and DSCP"""
            ecn = ip.icmp.payload.traffic_class
            if payload_len > 8:
                flags = ip.icmp.payload.tcp.data[13]
            else:
                flags = 0 #we don't care
                
            dscp = ecn >> 2
             
            [ece, cwr, ect] = ECNChain_trace.ecn_flags(ecn, flags, payload_len) # !!!!!Why is self.ecn... not working?
            return [ece, cwr, ect, ("DSCP: %u" %dscp)]
          
    def ecn_flags( ecn, flags, payload_len):
        
        """TCP ECE and CWR flags"""
        if payload_len > 8:                   
            if (flags >> 6) % 2:
                ece = "ECE.set"
            else:
                ece = "ECE.notset"                    
            if (flags >> 7) % 2:
                cwr = "CWR.set"
            else:
                cwr = "CWR.notset"         
        else:
            ece = "ECE??"
            cwr = "CWR??"
                
                
        """IP ECT FLAGS"""                
        ECT_ZERO = 0x02
        ECT_ONE = 0x01
        ECT_CE = 0x03

        ect = 'ecn_no_ect'

        if ecn & ECT_CE == ECT_ZERO:
            ect = 'ecn_ect0'
        if ecn & ECT_CE == ECT_ONE:
            ect = 'ecn_ect1'
        if ecn & ECT_CE == ECT_CE:
            ect = 'ecn_ce'  
                    
        return [ece, cwr, ect] 
    
    def syn_flags(flags):
        """TCP SYN/ACK flags """
        if (flags >> 1) % 2:
            syn = "SYN.set"
        else:
            syn = "SYN.notset"     
        if (flags >> 4) % 2:
            ack = "ACK.set"
        else:
            ack = "ACK.notset"           
         
        return [syn, ack] 
                
    def box_info6(ip, rev):     
        """ECN-specific Destination Stuff"""    
        if ip.tcp:
           
            """ECN-specific stuff like flags and DSCP"""
            ecn = ip.traffic_class
            flags = ip.tcp.data[13]                   
            payload_len = 9  #we don't care but needs to be bigger than 9 for ecn_flags to work properly
                       
            dscp = ecn >> 2                      
              
            [syn, ack] = ECNChain_trace.syn_flags(flags)
              
            """Calculating final hop with sequence number """
            [ece, cwr, ect] = ECNChain_trace.ecn_flags(ecn, flags, payload_len) # !!!!!Why is self.ecn... not working?

            return [ece, cwr, ect, syn, ack, ("DSCP: %u" %dscp)]              
             
        """ECN-specific traceroute Stuff""" 
        if ip.icmp6:
                    
            """length of payload that comes back to identify RFC1812-compliant routers"""
            pp = ip.icmp6.payload.payload
            payload_len = len(pp)
             
            """payload data of returning packet for bitwise comparison in merger""" 
            data = ip.icmp6.payload.data
      
            """ECN-specific stuff like flags and DSCP"""
            ecn = ip.icmp6.payload.traffic_class
            if payload_len > 8:
                flags = ip.icmp6.payload.payload[13]
            else:
                flags = 0 #we don't care
             
            [ece, cwr, ect] = ECNChain_trace.ecn_flags(ecn, flags, payload_len) # !!!!!Why is self.ecn... not working?
            return [ece, cwr, ect]   
