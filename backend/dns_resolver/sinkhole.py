"""
AegisDNS - DNS Sinkhole Response Generator
Constructs RFC-compliant DNS response packets for blocked domains.
Supports NULL route (0.0.0.0) and NXDOMAIN responses using dnspython.
"""

import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name


class DnsSinkhole:
    @staticmethod
    def create_blocked_response(query_message: dns.message.Message, sinkhole_ip: str = "0.0.0.0", response_type: str = "SINKHOLE_IP") -> dns.message.Message:
        """
        Creates a synthetic DNS response for a blocked domain query.
        """
        response = dns.message.make_response(query_message)
        response.flags |= dns.flags.AA # Authoritative Answer
        response.flags |= dns.flags.RA # Recursion Available

        if response_type == "NXDOMAIN":
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response

        # Default SINKHOLE_IP (0.0.0.0)
        if query_message.question:
            q = query_message.question[0]
            qname = q.name
            qtype = q.rdtype

            if qtype == dns.rdatatype.A:
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, sinkhole_ip)
                rrset = dns.rrset.from_rdata(qname, 10, rdata) # 10s TTL
                response.answer.append(rrset)
            elif qtype == dns.rdatatype.AAAA:
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, "::")
                rrset = dns.rrset.from_rdata(qname, 10, rdata)
                response.answer.append(rrset)
            elif qtype == dns.rdatatype.TXT:
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"AEGIS_DNS_BLOCKED_SINKHOLE"')
                rrset = dns.rrset.from_rdata(qname, 10, rdata)
                response.answer.append(rrset)
            else:
                # Return empty response with NOERROR for unsupported types
                response.set_rcode(dns.rcode.NOERROR)

        return response

