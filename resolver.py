import socket
import sys
from parse import decode_response


if (len(sys.argv) != 2):
    print("Invalid Arguments")
    exit(1)


def start_server():
    host = 'localhost'
    # port = 12345
    port = int(sys.argv[1])


    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #This line creates the server’s socket, called serverSocket. The first parameter indicates the address family; in particular,AF_INET indicates that the underlying network is using IPv4.The second parameter indicates that the socket is of type SOCK_DGRAM,which means it is a UDP socket (rather than a TCP socket, where we use SOCK_STREAM).

    serverSocket.bind(('localhost', port))
    #The above line binds (that is, assigns) the port number 12000 to the server’s socket. In this manner, when anyone sends a packet to port 12000 at the IP address of the server (localhost in this case), that packet will be directed to this socket.
    print('The server is ready to receive')
    while 1:
        dns_query, clientAddress = serverSocket.recvfrom(2048)
        #receive data from the client, now we know who we are talking with
        
        # print("dns query is", dns_query)

        # data = message.decode()
        # print("domain name is ",data)
        # modifiedMessage = message.upper()
        #change the case of the message received from client

        # perform dns resolving 
        response = dns_resolver(dns_query)


        # serverSocket.sendto(modifiedMessage, clientAddress)
        # message = "recieved yoooo" #REPLACE THIS WITH ACTUAL RESPONSE FROM NAME SERVERS 
        serverSocket.sendto(response, clientAddress)

    #send it back to client, need to specify the client address in sendto
    
    serverSocket.close()

def dns_resolver(dns_query):
    

    #parse the name.root file and store root servers as list 
    root_file_path = './named.root'

    root_server_list = parse_root_file(root_file_path)
    
    i = 0
    a_root_server = root_server_list[i]
   
    try:
        # Send the DNS query to the root DNS server
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        newSocket.sendto(bytes(dns_query), (a_root_server, 53))

        # Receive the DNS response
        response, server_address = newSocket.recvfrom(4096) 

        # Process and parse the DNS response as needed
        header_info, question_info, all_answers, all_authority, all_additional = decode_response(response)

    except socket.error as e:
        print(f"An error occurred: {e}")


    #now loop until we get answer != 0 
    # while (header_info[])
    while ((int.from_bytes(header_info['answer'], byteorder='big')) == 0):
        #loop and keep querying 
        server_record = find_new_record(header_info, all_authority, all_additional)
        # print("new record!!!!")
        # print(server_record)
        new_server_ip = server_record['data']
        # print("new server ip is", new_server_ip)
        newSocket.sendto(bytes(dns_query), (new_server_ip, 53))

        response, server_address = newSocket.recvfrom(4096)
        # print("huh")
        header_info, question_info, all_answers, all_authority, all_additional = decode_response(response)
        
    
    newSocket.close()
    
    return response

def find_new_record(header_info, all_authority, all_additional):
    #find server to use 
    if ((int.from_bytes(header_info['additional_rr'], byteorder='big')) > 0):
        # print("yo")
        # print(all_additional)
        for additional_records in all_additional:
            if ((int.from_bytes(additional_records['q_type'], byteorder='big')) == 1):
                return additional_records
                
    else: 

        # print(all_authority)
        for authority_records in all_authority:
            # if ((int.from_bytes(authority_records['q_type'], byteorder='big')) == 1):
            return authority_records



def parse_root_file(file_path):
    a_roots = []

    with open(file_path, 'r') as named_root_file:
        for line in named_root_file:
            if not line or line.startswith(';'):
                continue  # Skip empty lines or comments
            # print(line)
            parts = line.split()
            if (parts[2] == 'A'):
                # print(parts)
                a_roots.append(parts[-1])
            # if len(parts) == 2:
            #     ip_address, domain_name = parts
            #     roots.append((ip_address, domain_name))
    return a_roots

if __name__ == '__main__':
    start_server()