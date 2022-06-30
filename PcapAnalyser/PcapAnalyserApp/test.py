from scapy.all import *
# import vpython
#import graphviz
import pyx

a= rdpcap("./pcaps/test1.pcapng")
#print(cap[0].summary())

# print(p.conversations(type="jpg", target="> test.jpg"))
# p[0].pdfdump(layer_shift=1)
# p[0].psdump("/tmp/isakmp_pkt.eps",layer_shift=1)
# mytrace,err = traceroute (["www.google.com"])
# mytrace.graph(target=">trace.svg")
# mytrace.trace3D()
# a[0].pdfdump(layer_shift=1)
# a[0].psdump("./isakmp_pkt.jpeg",layer_shift=1)
a.make_table()