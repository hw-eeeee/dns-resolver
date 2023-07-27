import socket
import sys, time
from parse import decode_response, extract_header, extractKBits


if (len(sys.argv) != 2):
    print("Invalid Arguments")
    exit(1)


def start_server():
    host = 'localhost'
    port = int(sys.argv[1])


    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serverSocket.bind(('localhost', port))

    print('The server is ready to receive')
    
    while 1:
        dns_query, clientAddress = serverSocket.recvfrom(2048)
        #receive data from the client, now we know who we are talking with
        print("dns query is", dns_query)

        #TEST IF TIMEOUT WORKS
        # time.sleep(10)

        # perform dns resolving 
        response = dns_resolver(dns_query)

        if response == 1 or response == 2 or response == 3:
            response = str(response).encode('utf-8')

        #ERROR CHECKING!
        serverSocket.sendto(response, clientAddress)

    serverSocket.close()

def dns_resolver(dns_query):
    
    #parse the name.root file and store root servers as list 
    root_file_path = './named.root'

    root_server_list = parse_root_file(root_file_path)
    
    i = 0
    a_root_server = root_server_list[i]
   
    #loop through root server list- if succeed break! 
    while (i < len(root_server_list)):
        # Send the DNS query to the root DNS server
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        newSocket.sendto(bytes(dns_query), (a_root_server, 53))

        # Receive the DNS response
        response, server_address = newSocket.recvfrom(4096) 

        #ERROR CHECKING
        id, flags, question, answer, authority_rr, additional_rr = extract_header(response[:12])
        return_error = error_checking(flags)

        if return_error != 2 and return_error != 0:
            return return_error
        elif return_error == 2:
            # if not all root servers have been tried 
            if (i < len(root_server_list) - 1):
                i+=1 #LOOP TO NEXT ROOT SERVER- TRY ALL BEFORE RETURNING ERROR
            else: 
                return return_error

        else:
            # Process and parse the DNS response as needed
            header_info, question_info, all_answers, all_authority, all_additional = decode_response(response)
            break


    #now loop until we get answer != 0 
    while ((int.from_bytes(header_info['answer'], byteorder='big')) == 0):
        #loop and keep querying 
        server_record = find_new_record(header_info, all_authority, all_additional)
        new_server_ip = server_record['data']
        newSocket.sendto(bytes(dns_query), (new_server_ip, 53))

        response, server_address = newSocket.recvfrom(4096)
        header_info, question_info, all_answers, all_authority, all_additional = decode_response(response)

        #error checking
        flags = header_info['flags']
        return_error = error_checking(flags)
        if (return_error != 0):
            return return_error
        
    newSocket.close()
    
    return response



def error_checking(flags):
    #if bottom 4 bits are not 0, error (CHECK WHICH TYPE)

    bottom_4_int = extractKBits(int.from_bytes(flags, byteorder='big'), 4, 0)

    if (bottom_4_int == 0):
        print("NO ERROR")
        return 0
    elif (bottom_4_int == 1):
        print("FORMAT ERROR")
        return 1
    elif (bottom_4_int == 2):
        print("Server Error")
        return 2
    elif (bottom_4_int == 3):
        print("NO SUCH NAME ERROR")
        return 3




def find_new_record(header_info, all_authority, all_additional):
    #find server to use 
    if ((int.from_bytes(header_info['additional_rr'], byteorder='big')) > 0):
        for additional_records in all_additional:
            if ((int.from_bytes(additional_records['q_type'], byteorder='big')) == 1):
                return additional_records
    else: 

        for authority_records in all_authority:
            return authority_records



def parse_root_file(file_path):
    a_roots = []

    with open(file_path, 'r') as named_root_file:
        for line in named_root_file:
            if not line or line.startswith(';'):
                continue  # Skip empty lines or comments

            parts = line.split()
            if (parts[2] == 'A'):
                a_roots.append(parts[-1])
    return a_roots

if __name__ == '__main__':
    start_server()