from socket import *
from select import *
import sys, getopt
import time
import struct
from binascii import hexlify


class STP_segment:
    def __init__(self, syn=0, fin=0, ack=0, seq_num=0, ack_num=0, checksum = 'xxxx', payload=""):
		self.SYN = syn
		self.FIN = fin
		self.ACK = ack
		self.SEQ_NUM = seq_num
		self.ACK_NUM = ack_num        
		self.PAYLOAD = payload
		self.CHECKSUM = checksum
		self.PACKET = str(self.SYN) + str(self.FIN) + str(self.ACK)\
					   + "{0:08d}".format(self.SEQ_NUM) \
					   + "{0:08d}".format(self.ACK_NUM) + checksum + payload
		
 
def unpack_packet(data):
    return STP_segment(syn = int(data[0]),fin = int(data[1]), ack = int(data[2]),
                    seq_num = int(data[3:11]),
                    ack_num = int(data[11:19]), checksum = data[19:23], payload = data[23:])
					
def start(port):
	print('Started Connection...Waiting.....')
	ADDR = ('127.0.0.1', int(port))
	sock = socket(AF_INET, SOCK_DGRAM)  
	sock.bind(ADDR)
	data,ADDR = sock.recvfrom(1024)  
	syn_pkt = unpack_packet(data)
	if syn_pkt.SYN == 1:
		receiver_log.writelines("rcv \t%2.3f\tS\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), syn_pkt.SEQ_NUM, len(syn_pkt.PAYLOAD), syn_pkt.ACK_NUM))

		syn_ack_pkt = STP_segment(syn=1, seq_num=0, ack_num=syn_pkt.SEQ_NUM+1, ack=1)
		sock.sendto(syn_ack_pkt.PACKET, ADDR)
		receiver_log.writelines("snd \t%2.3f\tSA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), syn_ack_pkt.SEQ_NUM, len(syn_ack_pkt.PAYLOAD), syn_ack_pkt.ACK_NUM))

	data,ADDR = sock.recvfrom(1024)
	ack_pkt = unpack_packet(data)
	if ack_pkt.ACK == 1:
		print('Connected....')
		receiver_log.writelines("rcv \t%2.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), ack_pkt.SEQ_NUM, len(ack_pkt.PAYLOAD), ack_pkt.ACK_NUM))
		return sock,ack_pkt.SEQ_NUM, ADDR,1
	else:
		sock.close()
		exit("Fail to connect")
		
# https://forum.u-blox.com/index.php/14618/python-generate-checksums-validate-coming-serial-interface
# https://github.com/houluy/UDP/blob/master/udp.py
# https://security.stackexchange.com/questions/167473/spoofing-udp-checksum-using-scapy
# TextBook, v-6 , Page 202-203		
def calculate_checksum(src_p, dst_p, seq_n, ack_n, payload):
	hdr_msg = struct.pack('!HHLL',
						  src_p,
						  dst_p,
						  seq_n,
						  ack_n
						  )
	full_msg = hdr_msg + payload
	#print(full_msg)
	chksum = 0
	for i in range(0, len(full_msg), 2):
		a = int(hexlify(full_msg[i]), 16)
		#print(type(a))
		if i != len(full_msg) - 1:
			b = int(hexlify(full_msg[i+1]), 16)
		else:
			b = 0
		chksum = chksum + (a << 8) + b
		while chksum >> 16 != 0:
			chksum = chksum + chksum >> 16
	# one's complement
	chksum = ~chksum & 0xffff
	#print(hex(chksum))
	#print(chksum)
	chksum = '0000' + str(hex(chksum))
	chksum = chksum[-4:]
	#print(chksum)
	return chksum
	
		
# Start >>
receiver_log = open("Receiver_log.txt", "w")
rec_checksum_log = open("Receiver_CHECKSUM_log.txt", "w")


log_start = time.time()
ops, args = getopt.getopt(sys.argv[1:], " ")
port = args[0]
file_name = args[1]
sock, ack, ADDR, sequence_number =start(port)

f=open(file_name,'w')

#-----------for log--------------
amount_of_data = 0
nb_total_seg = 0
nb_data_seg = 0

nb_dup_seg = 0
nb_dup_ack = 0
nb_bit_err = 0
#------------------------------------
fin_received = False
while not fin_received:
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		seg, ADDR = sock.recvfrom(1024)
		seg = unpack_packet(seg)
		is_dup = False
		print('Received Seg# {}'.format(seg.SEQ_NUM))
		if seg.FIN == 1:
			print('Closing has been intitiated from Sender...')
			print('FIN Received')
			receiver_log.writelines("rcv \t%2.3f\tF\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))

			sock.sendto(STP_segment(ack=1, ack_num=seg.SEQ_NUM+1, seq_num=sequence_number).PACKET, ADDR)
			receiver_log.writelines("snd \t%2.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), sequence_number, 0, seg.SEQ_NUM+1))

			#close_wait
			b_n = 10000
			while b_n > 0:
				b_n -= 1
				
			print('ACK Sent....wait 5 seconds....close wait....')
			time.sleep(5)

			sock.sendto(STP_segment(fin=1, ack_num=seg.SEQ_NUM+1, seq_num=sequence_number).PACKET, ADDR)
			receiver_log.writelines("snd \t%2.3f\tF\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), sequence_number, 0, seg.SEQ_NUM+1))
			print('FIN Sent')
			fin_received = True
			break
		
		if fin_received:
			break
		else:
			# If not above, then it must be data packet that we have received...
			receiver_log.writelines("rcv \t%2.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))	
			nb_data_seg += 1
		
			c_sum = calculate_checksum(int(port), int(port), seg.SEQ_NUM, seg.ACK_NUM, seg.PAYLOAD)
			
			if c_sum != seg.CHECKSUM:
				nb_bit_err += 1
				rec_checksum_log.writelines('Corrupt >> Received CheckSUM : {}\t Calculated Checksum : {}\n'.format(seg.CHECKSUM, c_sum))
				print('Bit Error!')
				
			if ack == seg.SEQ_NUM and c_sum == seg.CHECKSUM:
				line = seg.PAYLOAD
				ack = seg.SEQ_NUM + len(line)
				f.write(line)
				
			if c_sum != seg.CHECKSUM or ack != seg.SEQ_NUM:
				# if a packet has a bit error...it will definitely be sent again....so increase duplicate count
				# if file is not getting written, that means duplicate seg received or out of seq seg received. i.e. dup seg will be received in future
				# nb of dup seg means that many time whatever ack will be sent, that will also be duplicated
				nb_dup_seg += 1
				nb_dup_ack += 1
				is_dup = True
					
			amount_of_data += len(seg.PAYLOAD)

			send_ack = STP_segment(ack_num=ack, seq_num=sequence_number)
			sock.sendto(send_ack.PACKET, ADDR)
			if not is_dup:
				receiver_log.writelines("snd \t%2.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), send_ack.SEQ_NUM, len(send_ack.PAYLOAD), send_ack.ACK_NUM))
			else:
				receiver_log.writelines("snd/DA\t%2.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), send_ack.SEQ_NUM, len(send_ack.PAYLOAD), send_ack.ACK_NUM))

			print('Send ACK {}'.format(send_ack.ACK_NUM))
		
	if fin_received:
		break

#Receive FINAL ACK here
print('Waiting for receiving FINAL ACK from sender')
final_ack_rcvd = False
while not final_ack_rcvd:
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		seg, ADDR = sock.recvfrom(1024)
		seg = unpack_packet(seg)
		if seg.ACK == 1:
			print('FINAL ACK Received....close socket..break while loop...finish log summary section...')
			receiver_log.writelines("rcv \t%2.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))
			sock.close()
			final_ack_rcvd = True
			break
		if final_ack_rcvd:
			break
	if final_ack_rcvd:
		break

# Summary for Log		
# 2 for open connection, 2 for close connection. There are many ways to log this, but I didn't want to declare more variables. That clutter the code more
nb_total_seg = nb_data_seg + 2 + 2

receiver_log.writelines('======================================================\n')
receiver_log.writelines("Amount of Data Received (bytes):%d\n"%amount_of_data)
receiver_log.writelines("Total segments received:%d\n"%nb_total_seg)
receiver_log.writelines("Data segments received:%d\n"%nb_data_seg)

receiver_log.writelines("Data Segments with bit errors:%d\n"%nb_bit_err)
receiver_log.writelines("Duplicate data segments received:%d\n"% nb_dup_seg)
receiver_log.writelines("Duplicate Acks sent:%d\n"%nb_dup_ack)
receiver_log.writelines('======================================================\n')