import socket
import sys
import random
import struct
import time, signal
from parse import decode_response, print_question, print_header, print_partial_header, print_RR

if len(sys.argv) <= 3 or len(sys.argv) >= 7 :
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name [timeout=5] [type=A]")
    exit(1)

def start_client():

    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    domain_name = sys.argv[3]

    #default 
    timeout = 5
    query_type = "A"

    if len(sys.argv) == 5:
        # see if arg[4] is timeout or query type by checking if its a number 
        if (sys.argv[4].isnumeric()):
            timeout = sys.argv[4]
        else: 
            query_type = sys.argv[4].upper() #fo case insensitivity 
    elif len(sys.argv) == 6:
        #both arguments there
        timeout = sys.argv[4]
        query_type = sys.argv[5].upper()

    
    run_query_with_timeout(domain_name, resolver_ip, resolver_port, int(timeout), query_type)


def timeout_handler(signum, frame):
    raise TimeoutError("Code execution took too long.")


def run_query_with_timeout(domain_name, resolver_ip, resolver_port, timeout, query_type):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        run_query(domain_name, resolver_ip, resolver_port, query_type) 
    except TimeoutError:
        print("Execution timed out!")
    finally:
        signal.alarm(0)  # Disable the alarm signal


def run_query(domain_name, resolver_ip, resolver_port, query_type):
    #create client’s socket. 
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #now construct a DNS query for the given name
    dns_query = create_DNS_query(domain_name, query_type)

    # UDP we explicilty specify the destination address + Port No for each message
    clientSocket.sendto(dns_query,(resolver_ip, resolver_port))

    returnedMessage, serverAddress = clientSocket.recvfrom(2048)

    #check if returned message is an error
    error_checking(returnedMessage, clientSocket, domain_name)

    clientSocket.close()

    #parse the message- decode it
    header_info, question_info, all_answers, all_authority, all_additional = decode_response(returnedMessage)

    
    
    #now check if answer section is all A type and if there are CNames that can be 
    #further resolved. Append the answers to a list
    ip_addresses = resolve_cnames(all_answers, resolver_ip, resolver_port, query_type)
    # print in dig formatting 
    print_partial_header(header_info)
    print_question(question_info)
    print_ip_addresses(ip_addresses)

    print()
    
    clientSocket.close()




def resolve_cnames(all_answers, resolver_ip, resolver_port, query_type):
    ip_addresses = []
    c_name_answers = []
    for answer in all_answers:
        ip_addresses.append(answer)
        if (int.from_bytes(answer['q_type'], byteorder='big')) == 5:
            c_name_answers.append(answer)

    while len(c_name_answers) > 0:
        # print("send query again")
        new_domain_name = c_name_answers[0]["data"]
        c_name_answers = []
        dns_query = create_DNS_query(new_domain_name, query_type)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        clientSocket.sendto(dns_query,(resolver_ip, resolver_port))
        returnedMessage, serverAddress = clientSocket.recvfrom(2048)
        header_info1, question_info1, all_answers1, all_authority1, all_additional1 = decode_response(returnedMessage)
    
        try:
            for answer in all_answers1:
                if answer not in ip_addresses:
                    ip_addresses.append(answer)
                if (int.from_bytes(answer['q_type'], byteorder='big')) == 5:
                    c_name_answers.append(answer)
        except:
            pass
    return ip_addresses




def error_checking(returnedMessage, clientSocket, domain_name):
    decoded_message = ''
    try: 
        decoded_message = returnedMessage.decode()
    except:
        pass

    if decoded_message != "":
        if decoded_message == "1":
            print("Error: Format error - The name server was unable to interpret the query.")
        
        elif decoded_message == "2":
            print("Error: Server failure - The name server was unable to process this query.")
        elif decoded_message == "3":
            print(f"Error: server can't find {domain_name}")
        else: 
            #other
            print(f"Error: {decoded_message}")
        clientSocket.close()
        exit(1)


def print_ip_addresses(ip_addresses):
    print("ANSWER SECTION:")
    for content in ip_addresses:
        print(f"{content['name']}\tQTYPE: ", end="")
        if (int.from_bytes(content['q_type'], byteorder='big') == 1):
            print("A", end="")
        elif (int.from_bytes(content['q_type'], byteorder='big') == 2):
            print("NS", end="")
        elif (int.from_bytes(content['q_type'], byteorder='big') == 5):
            print("CNAME", end = "")

        print(f"\tQCLASS:", end="") 
        if (int.from_bytes(content['q_class'], byteorder='big') == 1):
            print("IN", end="")

        print(f"\tTTL:{int.from_bytes(content['ttl'], byteorder='big')}\tDATA LENGTH:{content['data_len']}\tIP ADDRESS:{content['data']}")



# IMPLEMENTED FOR ALL TYPES OF QUERIES
def create_DNS_query(domain_name, query_type = 'A'):
    # DNS header fields
    transaction_id = 0x1337  # Random transaction ID, you can choose any value
    flags = 0x0100  # Standard query with recursion desired

    # Query fields
    qname = b''
    for part in domain_name.split('.'):
        qname += struct.pack('B', len(part))
        qname += part.encode()

    qname += b'\x00'  # Null-terminator for the domain name

    qtype = 0x0001
    if query_type == 'A':
        qtype = 0x0001  # Type A record (IPv4 address)
    
    elif query_type == 'MX':
        qtype = 0x000f  #Type Mail Exchange
        # print("mail exchange")

    elif query_type == 'NS':
        qtype = 0x0002  #Type Name server 
        # print("name server")
    
    elif query_type == 'CNAME':
        qtype = 0x0005  #Type CNAME
        # print("cname")

    elif query_type == 'PTR':
        qtype = 0x000c  #Type PTR
        # print("ptr")    
    else:
        print("Error: unknown query type")
        exit()

    qclass = 0x0001  # Internet class

    # Construct the DNS query packet
    dns_query = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
    dns_query += qname
    dns_query += struct.pack('!HH', qtype, qclass)

    # print(dns_query.hex())  
    return dns_query


if __name__ == '__main__':
    start_client()


