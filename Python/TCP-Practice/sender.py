import sys, getopt
from random import *
import time
from socket import *
from select import *
import os
import struct
from binascii import hexlify

class STP_segment:
	def __init__(self, syn=0, ack=0, fin=0, seq_num=0, ack_num=0, checksum = 'xxxx', payload=''):
		self.SYN = syn
		self.FIN = fin
		self.ACK = ack
		self.ACK_NUM = ack_num
		self.SEQ_NUM = seq_num
		self.PAYLOAD = payload
		#add checksum
		self.CHECKSUM = checksum
		self.PACKET = str(self.SYN) + str(self.FIN) + str(self.ACK)\
						+ "{0:08d}".format(self.SEQ_NUM) \
						+ "{0:08d}".format(self.ACK_NUM) \
						+ checksum + payload
		self.SEND_TIME = None

def unpack_packet(data):
    return STP_segment(syn = int(data[0]),fin = int(data[1]), ack = int(data[2]),
                    seq_num = int(data[3:11]),
                    ack_num = int(data[11:19]), checksum = data[19:23], payload = data[23:])
    
	
def three_way_handshake(ip, port):
	global sender_log
	ADDR = (ip, int(port))
	sock = socket(AF_INET, SOCK_DGRAM)
	seq = 0
	syn_segment = STP_segment(syn=1,seq_num=seq)
	sock.sendto(syn_segment.PACKET, ADDR)
	sender_log.writelines("snd\t\t\t%5.3f\tS\t%8d\t%3d\t%8d\n"%(round(time.time() - log_start, 2), syn_segment.SEQ_NUM, len(syn_segment.PAYLOAD), 0 ))

	data,ADDR = sock.recvfrom(1024)
	seg = unpack_packet(data)

	if seg.SYN == 1 and seg.ACK == 1:
		sender_log.writelines("rcv\t\t\t%5.3f\tSA\t%8d\t%3d\t%8d\n"%(round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM ))
		
		seq += 1
		sock.sendto(STP_segment(ack=1, ack_num = seg.SEQ_NUM+1, seq_num=seq).PACKET, ADDR)
		sender_log.writelines("snd\t\t\t%5.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seq, 0, seg.SEQ_NUM+1))
		# print("connection successful.....")
	else:
		sock.close()
		exit("Connection Failed!")
	return sock,ADDR,seq,seg.SEQ_NUM+1

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
	print(chksum)
	return chksum

def prepare_sender_window():
    global send_window
    global sequence_number
    global data
    while len(send_window) < MWS and data:
		# prepare data in list
		c_sum = calculate_checksum(int(receiver_port), int(receiver_port), sequence_number, acknowledge_number, data)
		print(c_sum)
		sender_checksum_log.writelines('{}\n'.format(c_sum))
		send_window.append(STP_segment(payload = str(data), seq_num = sequence_number, ack_num=acknowledge_number, checksum = c_sum))
		sequence_number += len(data)
		data = file.read(MSS)

	
def get_next_action():
	global sender_log
	global send_window
	global nb_of_dup_ack
	global last_ack
	global fast_retransmit
	global prev_est_rtt
	global prev_dev_rtt
	global TimeoutInterval
	inf, outf, errf = select([sock, ], [], [], 0)
	while inf: # get last ack
		recv_segment, ADDR = inf[0].recvfrom(1024)
		seg = unpack_packet(recv_segment)
		
		# Set TimeOut Dynamically >>
		if seg.ACK_NUM in timeOut_dict:
			time_now = round(time.time() - log_start, 3)
			sample_rtt = time_now - timeOut_dict[seg.ACK_NUM]
			#timeOut_log.writelines("%d\t%5.3f\n" % (seg.ack_num, sample_rtt))
			del timeOut_dict[seg.ACK_NUM]
			#print('Sample RTT {}'.format(sample_rtt))
			TimeoutInterval, prev_est_rtt, prev_dev_rtt = calculate_Timeout(prev_est_rtt, prev_dev_rtt, sample_rtt, gamma)
			TimeoutInterval /= 1000
			TimeoutInterval = round(TimeoutInterval, 3)
			timeOut_log.writelines('Sample RTT {}\tTimeOut {}\n'.format(sample_rtt, TimeoutInterval))
			#print('TimeOut {}'.format(TimeoutInterval))
		
		print('last ack {} rec ack {}'.format(last_ack, seg.ACK_NUM))
		
		if last_ack == seg.ACK_NUM: # Page-251 Figure 3.37....Still receiving last ack!!!
			sender_log.writelines("rcv/DA\t\t%5.3f\tA\t%8d\t%3d\t%8d\n"% (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))
			nb_of_dup_ack += 1
			fast_retransmit += 1
			if fast_retransmit >= 3: # Why 3? Refer: Week 5 20/08/2018 - 26/08/2018 Lecture Slide : 68 "Could trigger resend on receiving k" duplicate ACKs (TCP uses k = 3)"
				print('Fast RXT')
				fast_retransmit = 0
				return 'FastRetransmit', 0
		else:
			sender_log.writelines("rcv\t\t\t%5.3f\tA\t%8d\t%3d\t%8d\n"% (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))
			last_ack = seg.ACK_NUM
			for i in send_window:
				if seg.ACK_NUM == i.SEQ_NUM + len(i.PAYLOAD):
					send_window = send_window[send_window.index(i) + 1:] # shift send window to right by 1
					prepare_sender_window() # this will append one packet to send window
					return 'UpdateWindow', 0
					
		for i in send_window:
			if i.SEND_TIME:
				if time.time() > i.SEND_TIME + TimeoutInterval:
					return 'TimeOut',i #Need i to be retransmitted					
		
		return 'Nothing', 0
	return 'Nothing', 0
	
# To calculate sample_rtt, I have put the seq# and send time in a dict....then while receiving ack, I measured rtt....and from that--> TimeOut
# I deleted elements from dictionary after calculating the RTT...otherwise the dict will get very large, slow and ultimately fail
# But, Since I deleted the elements, everytime the dictionary only keeps track of unacked packets....that number is not that high
# if I uncomment one timeount log file in get_next_action() function, that keeps a track of how timeout evolves over time.
def calculate_Timeout(prev_est_rtt, prev_dev_rtt, sample_rtt, gamma_value):
	EstimatedRTT = 0.875 * prev_est_rtt + 0.125 * sample_rtt
	DevRTT = 0.75 * prev_dev_rtt + 0.25 * abs(sample_rtt - EstimatedRTT)
	TimeoutInterval = EstimatedRTT + gamma_value * DevRTT
	return TimeoutInterval, EstimatedRTT, DevRTT
	

# PLD Module code --- This is where evrything happens ---	
def send_data(segment):
	global sender_log
	global nb_drop
	global nb_seg_incl_drop_rxt
	global nb_duplicate
	global nb_corrupt
	global nb_pld
	global nb_order
	global nb_delay
	
	global timeOut_dict
	global order_dict
	global delay_dict
	
	nb_seg_incl_drop_rxt += 1
	segment.SEND_TIME = time.time()
	#timeOut_log.writelines("%d\t%5.3f\n" % (i.SEQ_NUM, round(time.time() - log_start, 2)))
	#print(timeOut_dict)
	if segment.SEQ_NUM not in timeOut_dict:
		timeOut_dict[segment.SEQ_NUM] = round(time.time() - log_start, 3)
		
		
	# I first check if any packet which is held in Order Dict, has been timeout or not....if, then send that immidiately
	# Start sending pDelay packets
	list_to_delete = []
	for i in delay_dict:		
		if delay_dict[i][0] <= time.time()*1000 + maxDelay: # Expired....
			list_to_delete.append(i)
			sock.sendto(delay_dict[i][1].PACKET, ADDR)
			sender_log.writelines("snd/dely\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), delay_dict[i][1].SEQ_NUM, len(delay_dict[i][1].PAYLOAD), delay_dict[i][1].ACK_NUM))
			
	#delete elements from Order Dict where counter has become zero...	
	for i in list_to_delete:
		del delay_dict[i]
	#End Sending pDelay packets
	
	
	if random() < pDrop:
		nb_drop += 1
		sender_log.writelines("drop\t\t%5.3f\tD\t%8d\t%3d\t%8d\n"%(round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
		nb_pld += 1
	else: # Add more and more PLD Conditions here
		
		# if a packet is not droppped, then we can counter down the held packets and may be counter becomes 0, then send those
		# I have not considered counting down twice while sending duplicate packet. Because that is actually same packet sending twice
		# Start sending pOrder packets
		list_to_delete = []
		for i in order_dict:
			order_dict[i][0] -= 1
			if order_dict[i][0] == 0:
				list_to_delete.append(i)
				sock.sendto(order_dict[i][1].PACKET, ADDR)
				sender_log.writelines("snd/rord\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), order_dict[i][1].SEQ_NUM, len(order_dict[i][1].PAYLOAD), order_dict[i][1].ACK_NUM))
				
		#delete elements from Order Dict where counter has become zero...	
		for i in list_to_delete:
			del order_dict[i]
		#End Sending pOrder packets
	
	
		if random() < pDuplicate: 
			nb_duplicate += 1
			sock.sendto(segment.PACKET, ADDR)
			sock.sendto(segment.PACKET, ADDR)
			sender_log.writelines("snd\t\t\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
			sender_log.writelines("snd\t\t\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
			nb_pld += 2
		else:
			if random() < pCorrupt:
				# Introduce 1 bit error and send	
				string = segment.PAYLOAD
				orig_len = len(string)
				c_data = string
				#test_log.writelines('To be corrupted : {}\n{}\n'.format(type(c_data),c_data))
				c_data = c_data[-1:] # last character
				#test_log.writelines('Before Corrupt:{}Type is {}\n'.format(c_data, type(c_data)))
				c_data = int(hexlify(c_data),16) # convert to int
				x = c_data
				c_data = c_data ^ 0x00000001 # change 1 bit/int
				
				# why this ? it just may occur that c_data is also 00000001. Then we think we introduced an error...but it's not  error.
				# the changed data is same as new data
				if x == c_data:
					c_data = c_data ^ 0x00000010
				if x == c_data:
					c_data = c_data ^ 0x00000100
				if x == c_data:
					c_data = c_data ^ 0x00001000
				if x == c_data:
					c_data = c_data ^ 0x00010000
				
				c_data = chr(c_data)
				#test_log.writelines('New Char after corrupt:{}Type is {}\n\n'.format(c_data, type(c_data)))
				# Padding with ~ to keep same string size....bit error can(and does...tested) cause size to be changed when converted back to string....
				string = string[:-1] + c_data + '~'*100
				string = string[ : orig_len]
				
				#test_log.writelines('After corrupt:{}\nType is {}\n\n'.format(type(string), string))
				
				corrupt_packet = STP_segment(payload = str(string), seq_num = segment.SEQ_NUM, ack_num=segment.ACK_NUM, checksum = segment.CHECKSUM)
				
				recal_chksum = calculate_checksum(int(receiver_port), int(receiver_port), corrupt_packet.SEQ_NUM, corrupt_packet.ACK_NUM, corrupt_packet.PAYLOAD)
				if recal_chksum != segment.CHECKSUM: # Ensure that error has happened
					sender_checksum_log.writelines('Corrupt >> Sending Checksum {}\n'.format(segment.CHECKSUM))
					nb_corrupt += 1
					sender_log.writelines("snd\t\t\t%5.3f\tDEr\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), corrupt_packet.SEQ_NUM, len(corrupt_packet.PAYLOAD), corrupt_packet.ACK_NUM))
					print('Send Corrupted Segment')
					sock.sendto(corrupt_packet.PACKET, ADDR)
					nb_pld += 1
				# Write a log file on the corrupt packets
				
			else:
				if random() < pOrder:
					print('Hold this in Order queue')
					# I will create a dictionary with key as seq#, value is a list [max_order, segment]
					# order_dict = {segment.seq_num = [max_order, segment.packet]}
					if segment.SEQ_NUM not in order_dict:
						order_dict[segment.SEQ_NUM] = [maxOrder, segment]
						nb_order += 1
						sender_log.writelines("rord\t\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
					print('Holding Done')
					# Whenever we send any packet, we will reduce this maxOrder counter for all elements present in dict
					# Then I will check if any count has become 0, then send that packet and delete that element from dict
					# This code will be at the beginning of the send_data function
				else:
					if random() < pDelay:
						print('Hold this in delay queue/dictionary')
						# This is same as Order
						if segment.SEQ_NUM not in delay_dict:
							delay_dict[segment.SEQ_NUM] = [time.time()*1000, segment] # take time in milisec..this will help calculate later
							nb_delay += 1
							sender_log.writelines("dely\t\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
					else:
						sock.sendto(segment.PACKET, ADDR)
						sender_log.writelines("snd\t\t\t%5.3f\tD\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), segment.SEQ_NUM, len(segment.PAYLOAD), segment.ACK_NUM))
						nb_pld += 1
		# Data Sent....wait for RTT and re-calculate Timeout in receiving funtion....Refer Lab 02....Code is in get_next_action()
		# Because I am getting ack there...
		


################################################ Start ################################################################################	
# >> Program starts here.......
	
# python sender.py receiver_host_ip receiver_port file.pdf MWS MSS gamma pDrop pDuplicate pCorrupt pOrder maxOrder pDelay maxDelay seed
# Get all parameters
ops, args = getopt.getopt(sys.argv[1:], " ")
receiver_host_ip = args[0]
receiver_port = args[1]
file_name = args[2]
MWS = int(args[3])
MSS = int(args[4])
gamma = int(args[5])
pDrop = float(args[6])
pDuplicate = float(args[7])
pCorrupt = float(args[8])
pOrder = float(args[9])
maxOrder = int(args[10])
pDelay = float(args[11])
maxDelay = int(args[12])
seed_input = int(args[13])

log_start = time.time()

MWS = MWS // MSS
seed(seed_input)


#test_log = open("snd_test_log.txt", "w")

sender_log = open("Sender_log.txt", "w")
sender_checksum_log = open("Sender_CHECKSUM_log.txt", "w")
# Start 3-way handshake
sock, ADDR, sequence_number,acknowledge_number = three_way_handshake(receiver_host_ip, receiver_port)

# get/open File/data
file = open(file_name, 'rb')
data = file.read(MSS)
# prepare data
send_window = []
prepare_sender_window()
last_ack = -1
fast_retransmit = 0

#---For Logging--------
# <event> <time> <type-of-packet> <seq-number> <number-of-bytes-data> <ack-number> 
filesize = os.stat(file_name).st_size
nb_of_dup_ack = 0
nb_seg_incl_drop_rxt = 0
number_of_retrans = 0
nb_drop = 0
nb_rxt_TO = 0
nb_rxt_FAST = 0
nb_duplicate = 0
nb_corrupt = 0
nb_pld = 0
nb_order = 0
nb_delay = 0
#----------------------

# Start sending data......

# EstimatedRTT = 0.875 * EstimatedRTT + 0.125 * SampleRTT
# DevRTT = (1 - 0.25) * DevRTT + 0.25 * |SampleRTT - EstimatedRTT|
# TimeoutInterval = EstimatedRTT + 4 * DevRTT)
# Use the initial value of EstimatedRTT = 500 milliseconds and DevRTT = 250 milliseconds
# TimeoutInterval = EstimatedRTT + gamma * DevRTT

prev_est_rtt = 500
prev_dev_rtt = 250

timeOut_log = open("TimeOut_log.txt", "w")

TimeoutInterval = prev_est_rtt + gamma * prev_dev_rtt
TimeoutInterval /= 1000

timeOut_dict = {}

order_dict = {}

delay_dict = {}

print('TimeOut {}'.format(TimeoutInterval))
#timeOut_log.writelines("%5.3f\n" % TimeoutInterval)

last_segment = None

while send_window:
	for i in send_window:
		last_segment = i
		
		received_result, received_to_send = get_next_action()
		
		if received_result == 'Nothing': #Normal Condition
			print('Send NORMAL Packet')
			#last_segment = i
			send_data(i)
			continue
		
		if received_result == 'TimeOut': # This is retransmit....because of timeout
			print('Send TimeOut Packet')
			send_data(received_to_send)
			#last_segment = i
			send_data(i)
			nb_rxt_TO += 1
			continue
        
		if received_result == "FastRetransmit": #This is Fast Retransmit because of higher ack received
			print('Send FastRetransmit Packet')
			if send_window:
				send_data(send_window[0]) # ReTransmitting Packet... 0 because the window moved...now...this is start point(this packet has not been acked yet)
			#last_segment = i
			send_data(i) # This is normal packet
			nb_rxt_FAST	+= 1
			continue
        
		if received_result == 'UpdateWindow':
			print('Send UpdateWindow Packet')
			#last_segment = i
			send_data(i)
			continue
		

print('Last Segment Sent >> seq# {} size = {}'.format(i.SEQ_NUM, len(i.PAYLOAD)))
expecting_ack = i.SEQ_NUM + len(i.PAYLOAD)
close = False
print('wait for ACK for last segment, then close connection')
while not close:
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		data, ADDR = sock.recvfrom(1024)
		seg = unpack_packet(data)
		sender_log.writelines("rcv\t\t\t%5.3f\tA\t%8d\t%3d\t%8d\n"% (round(time.time() - log_start, 2), seg.SEQ_NUM, len(seg.PAYLOAD), seg.ACK_NUM))
		
		if expecting_ack == seg.ACK_NUM:
			print('Received ack for final Data segment....close conn Now....initiate close....')
			close = True
			break
		if close:
			break
	if close:
		break

# I want to waste some time here....to discard all the pending acks that are in transmission 
# Ideally not needed. But sometimes, it may give error
print('Time waste')
print('For discarding on transmission acks from out of order segments')
print('Just wait while all those acks received to ensure not to mess up four way close')
big_number = 1000
while big_number > 0:
	big_number -= 1
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		data, ADDR = sock.recvfrom(1024)
		
print('Time Waste done')

# FIN ->
#	  <- ACK
#	  <- FIN
# ACK -> 
print('Send FIN')
sock.sendto(STP_segment(seq_num=sequence_number, fin=1, ack_num = acknowledge_number).PACKET, ADDR)
sender_log.writelines("snd\t\t\t%5.3f\tF\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), sequence_number, 0, acknowledge_number))
print('Waiting for ACK')
ack_rcvd = False
while not ack_rcvd:
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		data, ADDR = sock.recvfrom(1024)
		seg = unpack_packet(data)
		if seg.ACK == 1:
			print('ACK Received....I have set a 5 second close wait at receiver. Please wait...FIN will come in about 5 seconds')
			sender_log.writelines("rcv\t\t\t%5.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.SEQ_NUM, 0, seg.ACK_NUM))
			ack_rcvd = True
			break
		if ack_rcvd:
			break
	if ack_rcvd:
		break
print('Waiting for FIN')		
fin_rcvd = False
while not fin_rcvd:
	inf, outf, errf = select([sock, ], [], [], 0)
	if inf:
		data, ADDR = sock.recvfrom(1024)
		seg = unpack_packet(data)
		if seg.FIN == 1:
			print('FIN received....send final ACK, close connection...break from while loop')
			sender_log.writelines("rcv\t\t\t%5.3f\tF\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.SEQ_NUM, 0, seg.ACK_NUM))
			fin_rcvd = True
			print('fin_recd = True')
			# Send Final ACK
			sock.sendto(STP_segment(seq_num=seg.ACK_NUM, ack=1, ack_num = seg.SEQ_NUM + 1).PACKET, ADDR)
			sender_log.writelines("snd\t\t\t%5.3f\tA\t%8d\t%3d\t%8d\n" % (round(time.time() - log_start, 2), seg.ACK_NUM, 0, seg.SEQ_NUM+1))
			print('Final ACK Sent...closing from sender end...')
			sock.close()
			break
		if fin_rcvd:
			break
	if fin_rcvd:
		break

# Print Log-End section
x = 0
sender_log.writelines('======================================================\n')
sender_log.writelines('Size of the file (in Bytes) 				  : %d\n'%filesize)
sender_log.writelines('Segments transmitted (including drop & RXT)   : %d\n'%nb_seg_incl_drop_rxt)
sender_log.writelines('Number of Segments handled by PLD 			  : %d\n'%nb_pld)
sender_log.writelines('Number of Segments Dropped 					  : %d\n'%nb_drop)

sender_log.writelines('Number of Segments Corrupted 				  : %d\n'%nb_corrupt)
sender_log.writelines('Number of Segments Re-ordered 				  : %d\n'%nb_order)
sender_log.writelines('Number of Segments Duplicated 				  : %d\n'%nb_duplicate)
sender_log.writelines('Number of Segments Delayed 					  : %d\n'%nb_delay)

sender_log.writelines('Number of Retransmissions due to timeout 	  : %d\n'%nb_rxt_TO)
sender_log.writelines('Number of Fast Retransmissions 				  : %d\n'%nb_rxt_FAST)
sender_log.writelines('Number of Duplicate Acknowledgements received : %d\n'%nb_of_dup_ack)
sender_log.writelines('======================================================\n\n')

sender_log.writelines('*  Nb of duplicate count will not match between sender and receiver.\n')
sender_log.writelines('   Because in sender we are counting duplicates which occured because of pDuplicate.\n')
sender_log.writelines('   But there are many out of order, TimeOut, Fast RXT in receiver end which are duplicate\n\n')
sender_log.writelines('** Number of Segments handled by PLD = all_data_segments(excl handshake, close). normal + 2*dup + corr + drop? \nI have taken count of drop.\n\n')
sender_log.writelines('***Number of corrupted can be higher in Sender log than Receiver log.\n')
sender_log.writelines('   This is because a corrupted packet may arrive at receiver after sender has received the final data ack and .\n')
sender_log.writelines('   initiated closing and receiver also received FIN and started closing. \n')

print('Total Time Taken : {}'.format(time.time() - log_start))

#print(order_dict)