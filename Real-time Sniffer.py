'''
    Title: Real-time Packet Sniffer
    Author Saed El Dine Rajab
            '''
from socket import *
import struct,sys,re,time

def receiveData(s): #to receive raw data
    data = ''
    try:
        data = s.recvfrom(65565)#buffer size max length
    except timeout:
        data = ''
    except:
        sys.exc_info()
    return data[0]
 
# get Type of Service
def getTOS(data):
    #dictionary
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal cost", 1: "Minimize cost"}

#we shift to right to remove all 0 from the right
#   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
#   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
#   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
#   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
#   the 7th bit is empty and shouldn't be analyzed
 
    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
            reliability[R] + tabs + cost[M]
    return TOS
 

def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}
#we shift to right to remove all 0 from the right 
#   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
#   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
#   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13
 
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags
 
def getProtocol(protocolNr):#re module is regular expression
    protocolFile = open('Protocol.txt', 'r')#open the file and read it
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)#extract and mparse to string
    if protocol: # if protocol contain a value
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()#remove spaces
        return protocol
 
    else:
        return 'No such protocol.'

def getcurrentIP():
    HOST = gethostbyname(gethostname())
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    data = receiveData(s)
    unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
    destinationAddress = inet_ntoa(unpackedData[9])
    return str(destinationAddress)

def main():
    count=0;
    while True:
    # the public network interface
        HOST = gethostbyname(gethostname())
    # create a raw socket and bind it to the public interface
        s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
        s.bind((HOST, 0))
    # Include IP headers
        s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        s.ioctl(SIO_RCVALL, RCVALL_ON)
        data = receiveData(s)
    # get the IP header (the first 20 bytes) and unpack them
        unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])#B - unsigned char (1) H - unsigned short (2) s - string used to unpac string in IP 4 dots format
     
        version_IHL = unpackedData[0]
        version = version_IHL >> 4                  # version of the IP
        IHL = version_IHL & 0xF                     # internet header length
        TOS = unpackedData[1]                       # type of service
        totalLength = unpackedData[2]
        currentLength=int(totalLength)
        ID = unpackedData[3]                        # identification
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1FFF
        TTL = unpackedData[5]                       # time to live
        protocolNr = unpackedData[6]
        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8])#convert from string format to IP format
        destinationAddress = inet_ntoa(unpackedData[9])
        currentDest=[inet_aton(destinationAddress),inet_aton(getcurrentIP())]#convert from IP format to string format
        currentProtocol=(protocolNr)
        
        if currentLength==int(totalLength) or currentDest[1]==inet_aton (destinationAddress) :
            print "\n\n\n.\n\n\n "
            count+=1
        elif currentProtocol==str(protocolNr) and currentDest[1]==inet_aton (destinationAddress) and currentLength==int(totalLength):
            print "\n\n\nAlert\n\n\n "
            count+=1

        print "An IP packet with the size %i was captured." % (unpackedData[2])
        print "Raw data: " + data
        print "\nParsed data"
        print "Version:\t\t" + str(version)
        print "Header Length:\t\t" + str(IHL*4) + " bytes"
        print "Type of Service:\t" + getTOS(TOS)
        print "Length:\t\t\t" + str(totalLength)
        print "ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")"
        print "Flags:\t\t\t" + getFlags(flags)
        print "Fragment offset:\t" + str(fragmentOffset)
        print "TTL:\t\t\t" + str(TTL)
        print "Protocol:\t\t" + getProtocol(protocolNr)
        print "Checksum:\t\t" + str(checksum)
        print "Source:\t\t\t" + sourceAddress
        print "Destination:\t\t" + destinationAddress
        print "Payload:\n" + data[20:]
        # disabled promiscuous mode
        s.ioctl(SIO_RCVALL, RCVALL_OFF)#and clear the current IP to get new one
        if count==13:
            print "\n\nCRITICAL ALERT !!!!! DOS coming to "+destinationAddress+" From "+sourceAddress+" Shut down router quickly\n\n"
            time.sleep(10)#delay 10 sec to prevent system crash and to better ram managment because the program is runnig in real time
            count=0
    
main()
