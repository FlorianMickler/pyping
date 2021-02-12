import select
import socket
import time
import sys
import datetime

from impacket import ImpactDecoder, ImpactPacket

if len(sys.argv) < 3:
    print("Use: %s <src ip> <dst ip>" % sys.argv[0])
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]
timeout_ms = 1000

# Create a new IP packet and set its source and destination addresses.

ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(dst)

# Create a new ICMP packet of type TSTAMP.

icmp = ImpactPacket.ICMP()
icmp.set_icmp_type(icmp.ICMP_TSTAMP)

# Include a 12-character long payload inside the ICMP packet.
icmp.contains(ImpactPacket.Data(b'0'*12))

# Have the IP packet contain the ICMP packet (along with its payload).
ip.contains(icmp)

# Open a raw socket. Special permissions are usually required.
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
SO_TIMESTAMPNS = 35
s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)

def revByte(i):
    r = int.from_bytes(i.to_bytes(4,byteorder='big'), byteorder='little')
    ret = (r,i)
    if (r > i):
        ret = (i,r)
    return ret


ms_day=86400*1000
ms_qday = ms_day / 4
def compensateRollOver(ts, comp_ts):
    if ts < ms_qday and comp_ts > ms_day - ms_qday:
        ts = ts + ms_day
    return ts

# call with remote timestamp ts (unknown byte order) and the local ts with which we want
# to compare offset-wise (inspired by wireshark paket-icmp)
def getTS(ts, comp_ts):
    (ts1, ts2) = revByte(ts) #returns both byteorders sorted ascending
    if ts1 < ms_day and ts2 > ms_day:
        return ts1

    if ts2 < ms_day: #both might be valid
        nts1 = compensateRollOver(ts1, comp_ts)
        nts2 = compensateRollOver(ts2, comp_ts)
    else: # both are too big
        nts1 = ts1
        nts2 = ts2

    #return nearest to comp_ts
    if abs(nts1 - comp_ts) < abs(nts2 - comp_ts):
        return ts1
    return ts2

def getCurrentTimeMS():
    now = datetime.datetime.utcnow()
    return (now.hour*3600+now.minute*60+now.second)*1000+now.microsecond // 1000

def show_reply(ricmp, receive_time):
    rtime = getTS(ricmp.get_icmp_rtime(), receive_time)
    ttime = getTS(ricmp.get_icmp_ttime(), receive_time)

    print("Ping reply id #%d" % ricmp.get_icmp_id())
    print("seqence:  %s" % (ricmp.get_icmp_seq()))
    print("lifetime: %d" % ricmp.get_icmp_lifetime())
    print("otime:    %d" % ricmp.get_icmp_otime())
    print("rtime:    %d" % rtime)
    print("ttime:    %d" % ttime)
    print("received  %d" % receive_time)
    print("---------------")
    way2 = receive_time - ttime
    way1 = rtime - ricmp.get_icmp_otime()
    trueWay = (way1+way2)/2 # if the runtime is symmetric
    offset = way2 - trueWay #offset of the remote machine
    overall = receive_time - ricmp.get_icmp_otime() #overall time
    remoteTime = ttime - rtime #time on remote machine
    print("way1      %d" % way1)
    print("way2      %d" % way2)
    print("offset:   %d" % offset)
    print("onRemote: %d" % remoteTime)
    print("overallT: %d" % overall)
    print("")

seq_id = 0

while 1:
    # Give the ICMP packet the next ID in the sequence.
    seq_id += 1
    icmp.set_icmp_id(0)
    icmp.set_icmp_seq(seq_id)

    icmp.set_icmp_otime(getCurrentTimeMS())
    # Calculate its checksum.
    icmp.set_icmp_cksum(0)
    icmp.auto_checksum = 1

    # Send it to the target host.
    s.sendto(ip.get_packet(), (dst, 0))

    # Wait for incoming replies.
    start_time = getCurrentTimeMS()
    delta_t = 0
    while delta_t < timeout_ms:
        timeout_left = (timeout_ms - delta_t) / 1000
        #print("timeout_left %f" % timeout_left)
        if s in select.select([s],[],[], timeout_left)[0]:
            reply_receive = getCurrentTimeMS()
            delta_t = start_time - reply_receive

            reply = s.recvfrom(2000)[0]
            # Use ImpactDecoder to reconstruct the packet hierarchy.
            rip = ImpactDecoder.IPDecoder().decode(reply)
            # Extract the ICMP packet from its container (the IP packet).
            ricmp = rip.child()

            # If the packet matches, report it to the user.
            if rip.get_ip_dst() == src and rip.get_ip_src() == dst and icmp.ICMP_TSTAMPREPLY == ricmp.get_icmp_type():
                if ricmp.get_icmp_seq() != seq_id:
                    #drop packet
                    print("dropped old answer: seq #%d" % ricmp.get_icmp_seq())
                else:
                    show_reply(ricmp, reply_receive)
                    delta_t = timeout_ms
    time.sleep(1) #wait 1 sec between timestamp requests
