from scapy.all import *
# import vpython
#import graphviz
import pyx
import os
import matplotlib.pyplot as plt
a= rdpcap("./pcaps/test1.pcapng")
b= rdpcap("./pcaps/SSHv2.cap")
#print(cap[0].summary())

# print(p.conversations(type="jpg", target="> test.jpg"))
# p[0].pdfdump(layer_shift=1)
# p[0].psdump("/tmp/isakmp_pkt.eps",layer_shift=1)
# mytrace,err = traceroute (["www.google.com"])
# print(type(mytrace))
# mytrace.graph(target=">trace.svg")
# mytrace.trace3D()
# a[0].pdfdump(layer_shift=1)
# a[0].psdump("./isakmp_pkt.jpeg",layer_shift=1)
# a[0].pdfdump("./first",layer_shift=1)

# a[0].show()
# a[0].summary()
# ls(a[0])
# b[5].show()
#2hexdump(b[5])
# a.show()
# hexdump(b[5])
# ls(b[5])
# print(a)
# print(type(a[0]))
# print("----------")
# print(type(a[0].len))
# a.plot(lambda x:[x.len])
# c, b = sr(IP(dst="www.target.com")/TCP(sport=[RandShort()]*1000))
# c.plot(lambda x:x[1].id)
# for i in a:
#     i[IP]
# b.summary()
# b.command()
# plot()

import threading

from scapy.all import *

import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.style
from matplotlib import animation
import numpy as np

mpl.style.use('ggplot') # fivethirtyeight

WINDOW = 120
FPS = 4

counters = {1: 0, 2: 0}

x = (np.arange(-WINDOW, 0, dtype=np.float) + 1)/FPS
y = {i: [] for i in counters}

def callback(pkt):
    if IP not in pkt:
        return
    subnet = int(pkt[IP].src.split('.')[2])
    if subnet in counters:
        counters[subnet] += 1


def update_plot(i, line1):
    global y
    for i in counters:
        y[i].append(counters[i] * FPS)
        counters[i] = 0
        y[i] = y[i][-WINDOW:]
        lines[i].set_data([x[-len(y[i]):], y[i]])
    return lines.values()


if __name__ == '__main__':
    mpl.rcParams['toolbar'] = 'None'
    fig = plt.figure(figsize=(10, 4))
    lines = {i: plt.plot([],[], lw=2, label='link {}'.format(i))[0]
             for i in counters}
    plt.legend(loc='upper left')
    plt.ylabel('packets/s')
    plt.xlabel('time [s]')
    plt.xlim(x[0], x[-1])
    plt.ylim(0, 750)
    plt.tight_layout()
    ani = animation.FuncAnimation(
        fig, update_plot, fargs=(lines,),
        frames=None, interval=int(1000.0/FPS), blit=False)

    th = threading.Thread(
        target=sniff,
        kwargs=dict(prn=callback, filter='tcp and src net 10.45', store=0))

    th.daemon = True
    th.start()

    plt.show(block=True)