from socket import *
import struct
import sys
import re
import os

 
# receive a datagram
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print "An error happened: ",sys.exc_info()[1]
    return data[0]
 
# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}
 
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
 
# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}
 
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
 
# get protocol: 8 bits
def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()
        return protocol
 
    else:
        return 'No such protocol.'
 
#Get data from IP header 
def IPparcer(data):
    try:
        # get the IP header (the first 20 bytes) and unpack them
        # B - unsigned char (1)
        # H - unsigned short (2)
        # s - string
        unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
 
        version_IHL = unpackedData[0]
        version = version_IHL >> 4                  # version of the IP
        IHL = version_IHL & 0xF                     # internet header length
        TOS = unpackedData[1]                       # type of service
        totalLength = unpackedData[2]
        ID = unpackedData[3]                        # identification
        flags = unpackedData[4]
        fragmentOffset = unpackedData[4] & 0x1FFF
        TTL = unpackedData[5]                       # time to live
        protocolNr = unpackedData[6]
        checksum = unpackedData[7]
        sourceAddress = inet_ntoa(unpackedData[8])
        destinationAddress = inet_ntoa(unpackedData[9])

        print "An IP packet with the size %i was captured." % (unpackedData[2])
        print "Raw data: " + data
        print "\nParsed data oh IP header"
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
    except Exception,e:
        print 'Something in IPparcer go wrong..'

#Get data from TCP header
#Try to take 80or 8080 ports
def TCPparcer(data):
    try:
        data3 = struct.unpack('!BBHHHBBH4s4s', data[:20])
        cath_lenth_TCP = data3[2]
        print "Normal length of packet\n"
        print cath_lenth_TCP
        if cath_lenth_TCP >= 42:
            try:
                tcph = struct.unpack('!HHLLBBHHH' , data[20:40])
                res = IPparcer(data)
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                print '\n\nTCP header info'
                print 'Source Port : \t\t' + str(source_port)  
                print 'Dest Port : \t\t' + str(dest_port) 
                print 'Sequence Number : \t' + str(sequence) 
                print 'Acknowledgement : \t' + str(acknowledgement) 
                print 'TCP header length : \t' + str(tcph_length)
                total_lenght = tcph_length + 20
                print 'Payload:' + data[total_lenght:]
                return dest_port
                #if tcph[1] == 80:
                    try:
                        data2 = struct.unpack('!BBHHHBBH4s4s' , data[:20])
                        length = data2[2]
                        if length >= 42:
                            try:
                                res = IPparcer(data)
                                print '\n\nTCP header info'
                                print 'Source Port : \t\t' + str(source_port)  
                                print 'Dest Port : \t\t' + str(dest_port) 
                                print 'Sequence Number : \t' + str(sequence) 
                                print 'Acknowledgement : \t' + str(acknowledgement) 
                                print 'TCP header length : \t' + str(tcph_length)
                            except Exception,e :
                                print "Unexpected error after length:", sys.exc_info()[1]
                        else:
                            print "Too little string and definetly not HTTP"
                    except Exception, e:
                        print "Unexpected error: ", sys.exc_info()[1]
                #else:
                #    print "It's no 80 port "

                #if tcph[1] == 8080:
                    try:
                        data2 = struct.unpack('!BBHHHBBH4s4s', data[:20])
                        length = data2[2]
                        if length >= 42:
                            try:
                                res = IPparcer(data)
                                print '\n\nTCP header info'
                                print 'Source Port : \t\t' + str(source_port)  
                                print 'Dest Port : \t\t' + str(dest_port) 
                                print 'Sequence Number : \t' + str(sequence) 
                                print 'Acknowledgement : \t' + str(acknowledgement) 
                                print 'TCP header length : \t' + str(tcph_length)
                            except Exception,e:
                                print "Unexpected error:", sys.exc_info()[1]
                        else:
                            print "Too little string and definetly not HTTP"
                    except Exception, e:
                        print "Unexpected error: ", sys.exc_info()[1]
                #else:
                #    print "It's no 8080 port "
                #except Exception as e:
                #print "Unexpected error 10", sys.exc_info()[1]
        else:
            error4 = 'Too little for indeed packet'
            return error4    
    except Exception, e:
        print 'There is something go wrong..', sys.exc_info()[1]

#Find HTTP in data
def Find_Http(data):
    s = data
    s2 = "HTTP"
    return s.find(s2,20)
#main
def main():
    # the public network interface
    HOST = gethostbyname(gethostname())
 
    # create a raw socket and bind it to the public interface
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind((HOST, 80))
 
    # Include IP headers
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    s.ioctl(SIO_RCVALL, RCVALL_ON)
    data = receiveData(s)

    #Try to find HTTP in packet
    str1 = data[20:]
    if 'HTTP' in str1:
        res = TCPparcer(data)
        f1 = open("dump.txt", 'a')
        f1.write(data[20:])
        # Необходимо добавить поиск итресных вещей в HTTP трафике, такие как пароли логины и мыла
        # При нахождении необходимых вещей необходимо отдельно вытаскивать их для дальнейшего использования, + желательно вытаскивать целый сайт или хотя бы его урл для того, что бы в дальнейшем применить MITM уязвимость
        print "\n\nData has been catched"
    else:
        #if HTTP doesn't found try to take data from packet and after that create new packet
        res = TCPparcer(data)
        print '______'*13
        print '______'*13
        print '\n',res 
        print '\n\n'
        if res != 80:
            main()
        elif 'HTTP' in str1:
            print '+'*8
            print "Data has been catched"
        else:
            main()

    # disabled promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)

if __name__ == '__main__':
    main()
