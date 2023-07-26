import socket
import sys
import random
import struct


def decode_response(returnedMessage):
    # print(returnedMessage)
    # print("byte converted to hexadecimal value:",returnedMessage.hex())
    #HEADER SECTION
    id, flags, question, answer, authority_rr, additional_rr = extract_header(returnedMessage[:12])
    print_header(id, flags, question, answer, authority_rr, additional_rr)

    #QUESTION SECTION 
    domain, q_type, q_class, new_index = extract_question_section(returnedMessage)
    print_question(domain, q_type, q_class)

    #RESOURCE RECORDS
    print("ANSWERS")    #ANSWER SECTION
    i = 0
    while i < int.from_bytes(answer, byteorder='big'):
        print(f"Answer {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        print_RR(name, q_type, q_class, ttl, data_len, data)
        i += 1
    
    print("AUTHORITY")    #AUTHORITY SECTION
    i = 0
    while i < int.from_bytes(authority_rr, byteorder='big'):
        print(f"Authority {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        print_RR(name, q_type, q_class, ttl, data_len, data)
        i += 1
    
    print("ADDITIONAL")    #ADDITIONAL SECTION
    i = 0
    while i < int.from_bytes(additional_rr, byteorder='big'):
        print(f"Additional {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        print_RR(name, q_type, q_class, ttl, data_len, data)
        i += 1

#PRINTING FUNCTIONS
def print_header(id, flags, question, answer, authority_rr, additional_rr):
    print("HEADER")
    print("    TRANSACTION ID:", hex(int.from_bytes(id, byteorder='big')))
    print("    FLAGS:", hex(int.from_bytes(flags, byteorder='big')))
    print("    QUESTIONS:", int.from_bytes(question, byteorder='big'))
    print("    ANSWER RRs:", int.from_bytes(answer, byteorder='big'))
    print("    AUTHORITY RRs:", int.from_bytes(authority_rr, byteorder='big'))
    print("    ADDITIONAL RRs:", int.from_bytes(additional_rr, byteorder='big'))
    print()

def print_question(domain, q_type, q_class):
    print("QUESTION")
    print("    DOMAIN NAME:", domain)
    print("    QTYPE:", int.from_bytes(q_type, byteorder='big'))
    print("    QCLASS:", int.from_bytes(q_class, byteorder='big'))
    print()

def print_RR(name, q_type, q_class, ttl, data_len, data):
    print("    NAME:", name)
    print("    QTYPE:", int.from_bytes(q_type, byteorder='big'))
    print("    QCLASS:", int.from_bytes(q_class, byteorder='big'))
    print("    TTL:", int.from_bytes(ttl, byteorder='big'))
    print("    DATA LENGTH:", data_len)
    print("    RDATA:", data)


#HEADER SECTION
def extract_header(response):
    
    id = response[:2]               # id: first 16 bits (2 bytes) 
    flags = response[2:4]           # flags next 16 bits
    question = response[4:6]        # question count next 16 bits 
    answer = response[6:8]          # answer count next 16 bits 
    authority_rr = response[8:10]   # authority rr count next 16 bits  
    additional_rr = response[10:12] # additional rr count next 16 bits

    return id, flags, question, answer, authority_rr, additional_rr

#QUESTION SECTION
def extract_question_section(response):
    domain, index, flag = extract_domain_name(response, 12)
    q_type, q_class, index = extract_qtype_class(response, index)

    return domain, q_type, q_class, index

def extract_qtype_class(response, index):
    #q class and type (2 octet), index_count increment 
    q_type = response[index:index+2]
    index+=2

    q_class = response[index:index+2]
    index+=2

    return q_type, q_class, index


#extracts domain name from server response
def extract_domain_name(response, starting_index):
    # bob = 0
    flags = False
    index = starting_index
    domain_name_parts = []

    #loop through response
    while True:
        # check if it's a pointer 
        # pointer = check_pointer(response[index:index + 2])
        # if (pointer == True):
        #     flags = True
        #     break

        label_length = response[index]
        # print("EXTRACTED RESPONSE IS", response[index])
        # print("extracted partial is", response[index:index + 2])
        # as_an_int = int.from_bytes(response[index:index + 2], byteorder='big')

        # index_number = extractKBits(as_an_int, 14, 0)
        # print("NEW INDEX NEBER IS",index_number)

        # print("EXTRACTED RESPONSE IN BYTES", response[index:])
        index += 1

        # find the end of domain name and break
        if label_length == 0:
            break

        # for pointers # TODO change to a better if statement (this is like hard coding)
        if label_length == 192:
            # print('HIIIIIIIIIII')
            index -= 1
            # print("extracted partial is", response[index:index + 2])
            # print("in hex this is ", response[index:index + 2].hex())
            as_an_int = int.from_bytes(response[index:index + 2], byteorder='big')

            index_number = extractKBits(as_an_int, 14, 0)
            # print("NEW INDEX NEBER IS",index_number)
            # print("WTFFFF", response[47:])
            flags = True
        
            break

        # Read the label itself and append it to the list of domain name parts
        label = response[index : index + label_length].decode('utf-8')
        domain_name_parts.append(label)
        index += label_length

    # join domain name
    domain_name = '.'.join(domain_name_parts)
    
    return domain_name, index, flags



# RESOURCE RECORDS
def extract_resource_record(response, curr_index):
    # print("???")
    # print("RRS RECORDS")
    #find the domain (could be compressed or not)
    name, new_index = rr_name_finder(response, curr_index)

    #get type and class
    q_type, q_class, new_index = extract_qtype_class(response, new_index)

    #next 4 bytes is ttl 
    ttl = response[new_index: new_index + 4]
    new_index = new_index + 4  #increment to get to data len

    #data len (2 byte)
    data_len = int.from_bytes(response[new_index:new_index + 2], byteorder='big')
    # print(response[new_index:new_index + 2].hex())
    
    new_index = new_index + 2   #increment to get rdata 
    # print(response[new_index:].hex())
    

    # rdata (different for each one)
    if int.from_bytes(q_type, byteorder='big') == 1:
        # A data- A 32 bit Internet address.
        ip_address_raw = response[new_index:new_index + 4]
        data = socket.inet_ntoa(ip_address_raw)
        new_index = new_index + 4

    elif int.from_bytes(q_type, byteorder='big') == 2:
        # NS data 
        data_list = []
        # print("ijsdfhoijdfhiodhfsoiau", response[new_index:].hex())
        data, new_index, flags = extract_domain_name(response, new_index)
        data_list.append(data)
        # print("post extract domain name index", new_index)
        #
        if (flags == True):
            # theres additional data thats a pointers
            # print("IT NOT FINISHED")
            #find it 
            # print(response[new_index:new_index+2])
            # print(response[new_index:new_index+4])
            two_bytes = response[new_index:new_index + 2]
            # print(response[new_index:new_index + 2].hex())

            if (check_pointer(two_bytes) == True):
                #if first two bits are 1s, its a pointer 
                # figure out it's index and pass into domain extractor 

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                data = '.'.join(data_list)
                # print(data)
                # print(response[new_index:].hex())
                # print()
                # print(response[new_index + 2:].hex())
                # new_index = curr_index + 2
                new_index = new_index + 2
            # check_pointer(response[new_index:new_index+2])
        # data, new_index = name_finder(response, new_index)

        # new_index = new_index + 2

    elif int.from_bytes(q_type, byteorder='big') == 5:
        #CNAME data 
        # data, new_index, flags = extract_domain_name(response, new_index)
        # # data, new_index = rr_name_finder(response, new_index)

        data_list = []
        # print("ijsdfhoijdfhiodhfsoiau", response[new_index:].hex())
        data, new_index, flags = extract_domain_name(response, new_index)
        data_list.append(data)
        # print("post extract domain name index", new_index)
        #
        if (flags == True):
            # theres additional data thats a pointers
            # print("IT NOT FINISHED")
            #find it 
            # print(response[new_index:new_index+2])
            # print(response[new_index:new_index+4])
            two_bytes = response[new_index:new_index + 2]
            # print(response[new_index:new_index + 2].hex())

            if (check_pointer(two_bytes) == True):
                #if first two bits are 1s, its a pointer 
                # figure out it's index and pass into domain extractor 

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                data = '.'.join(data_list)
                # print(data)
                # print(response[new_index:].hex())
                # print()
                # print(response[new_index + 2:].hex())
                # new_index = curr_index + 2
                new_index = new_index + 2

    # elif int.from_bytes(q_type, byteorder='big') == 18:
    #     print("AAAA")
    else:
        # print()
        # print(response[new_index:new_index + 16].hex())
        data_potential = bytes_to_ipv6_address(response[new_index:new_index + 16])
        # print(data_potential)
        # print(socket.inet_ntoa(response[new_index:new_index + 16]))
        # new_index = new_index + 16
        data = data_potential
        new_index = new_index + 16
        

    return name, q_type, q_class, ttl, data_len, data, new_index

def bytes_to_ipv6_address(raw_bytes):
    # Convert raw bytes to a string of hexadecimal digits
    hex_str = ''.join('{:02x}'.format(byte) for byte in raw_bytes)

    # Insert colons to format the IPv6 address
    ipv6_address = ':'.join(hex_str[i:i+4] for i in range(0, len(hex_str), 4))

    return ipv6_address



#TODO: rename and rewrite this with the logic added in rdata of the extract_resource_record function!!!
def rr_name_finder(response, curr_index):
    #    - a pointer
    #    - a sequence of labels ending in a zero octet (normal address)
    #    - a sequence of labels ending with a pointer

    # - a pointer
    # (check first 2 bits of response)
    first_two_bytes = response[curr_index:curr_index + 2]
    # print("FROM RR", first_two_bytes)

    if (check_pointer(first_two_bytes) == True):
        #if first two bits are 1s, its a pointer 
        # figure out it's index and pass into domain extractor 

        as_an_int = int.from_bytes(first_two_bytes, byteorder='big')
        index_number = extractKBits(as_an_int, 14, 0)
        name, ignore, flags = extract_domain_name(response, index_number)
        return_index = curr_index + 2

    else:
        # else, address (use function to decode the rr name)
        name, new_index, flags = extract_domain_name(response, curr_index)
        return_index = new_index

        #check if return index has 1 as first 2 bits 


    # print("extracted name is ", name)
    return name, return_index

#returns true if response pointer
def check_pointer(first_two_bytes):
    # print("first two bytes", first_two_bytes)

    #check if first 2 bits is 1 and 1 
    as_an_int = int.from_bytes(first_two_bytes, byteorder='big')

    if (extractKBits(as_an_int, 1, 16) == 1) and (extractKBits(as_an_int, 1, 15) ==1):
        return True

    return False


def extractKBits(num,k,p):
 
     # convert number into binary first
     binary = bin(num)
 
     # remove first two characters
     binary = binary[2:]
 
     end = len(binary) - p
     start = end - k + 1
 
     # extract k  bit sub-string
     kBitSubStr = binary[start : end+1]
 
     # convert extracted sub-string into decimal again
     return (int(kBitSubStr,2))

