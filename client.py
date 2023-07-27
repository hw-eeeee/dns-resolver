import socket
import sys
import random
import struct
from parse import decode_response

if len(sys.argv) != 4:
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name")
    exit(1)

def start_client():

    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    domain_name = sys.argv[3]

    #create client’s socket. 
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #now construct a DNS query for the given name
    dns_query = create_DNS_query(domain_name)

    # UDP we explicilty specify the destination address + Port No for each message
    clientSocket.sendto(dns_query,(resolver_ip, resolver_port))
    # print(dns_query)
    # decode_response(dns_query)

    returnedMessage, serverAddress = clientSocket.recvfrom(2048)
    clientSocket.close()
    # print the received message
    # print("yo", returnedMessage)
    # print(serverAddress, "\n")

    #parse the message- decode it
    header_info, question_info, all_answers, all_authority, all_additional = decode_response(returnedMessage)
    
    #now check if answer section is all A type and if there are CNames that can be 
    #further resolved. Append the answers to a list
    ip_addresses = []
    c_name_answers = []
    for answer in all_answers:
        ip_addresses.append(answer)
        if (int.from_bytes(answer['q_type'], byteorder='big')) == 5:
            c_name_answers.append(answer)

    # print("ip addresses", ip_addresses)
    # print()
    # print(c_name_answers)

    #if theres cnames
    if len(c_name_answers) > 0:
        # print("send query again")
        new_domain_name = c_name_answers[0]["data"]
        dns_query = create_DNS_query(new_domain_name)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        clientSocket.sendto(dns_query,(resolver_ip, resolver_port))
        returnedMessage, serverAddress = clientSocket.recvfrom(2048)
        header_info1, question_info1, all_answers1, all_authority1, all_additional1 = decode_response(returnedMessage)
    
    try:
        for answer in all_answers1:
            if answer not in ip_addresses:
                ip_addresses.append(answer)
    except:
        pass

    # print("ip addresses", ip_addresses)

    # print in dig formatting 
    print_ip_addresses(ip_addresses)
    
    clientSocket.close()



def print_ip_addresses(ip_addresses):
    for content in ip_addresses:
        print(f"{content['name']}\tQTYPE: {int.from_bytes(content['q_type'], byteorder='big')}\tQCLASS: {int.from_bytes(content['q_class'], byteorder='big')}\tTTL:{int.from_bytes(content['ttl'], byteorder='big')}\tDATA LENGTH:{content['data_len']}\tIP ADDRESS:{content['data']}")




# automatically type A if no further arguments are given
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
    
    qclass = 0x0001  # Internet class

    # Construct the DNS query packet
    dns_query = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
    dns_query += qname
    dns_query += struct.pack('!HH', qtype, qclass)

    return dns_query


if __name__ == '__main__':
    start_client()
    # print("help")
    # print(socket.inet_ntoa(b'\xa2\x9f\x18\xb3'))


