import socket
import sys
import random
import struct


def decode_response(returnedMessage):
    # print(returnedMessage)

    #HEADER SECTION
    id, flags, question, answer, authority_rr, additional_rr = extract_header(returnedMessage[:12])
    header_info = {
    "id": id,
    "flags": flags,
    "question": question, 
    "answer": answer, 
    "authority_rr": authority_rr, 
    "additional_rr": additional_rr
    }
    # print_header(header_info)
    
    #QUESTION SECTION 
    domain, q_type, q_class, new_index = extract_question_section(returnedMessage)
    question_info = {
        "domain": domain,
        "q_type": q_type,
        "q_class": q_class
    }
    # print_question(question_info)



    #RESOURCE RECORDS
    # print("ANSWERS")    #ANSWER SECTION
    all_answers = []
    i = 0
    while i < int.from_bytes(answer, byteorder='big'):
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        record = {
            "name": name,
            "q_type": q_type,
            "q_class": q_class, 
            "ttl": ttl,
            "data_len": data_len,
            "data": data
        }
        # print_RR(record)

        all_answers.append(record)
        i += 1
    
    # print("\n\nAUTHORITY")    #AUTHORITY SECTION
    all_authority = []
    i = 0
    while i < int.from_bytes(authority_rr, byteorder='big'):
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        record = {
            "name": name,
            "q_type": q_type,
            "q_class": q_class, 
            "ttl": ttl,
            "data_len": data_len,
            "data": data
        }
        # print_RR(record)

        all_authority.append(record)
        i += 1
    
    # print("\n\nADDITIONAL")    #ADDITIONAL SECTION
    all_additional = []
    i = 0
    while i < int.from_bytes(additional_rr, byteorder='big'):
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        record = {
            "name": name,
            "q_type": q_type,
            "q_class": q_class, 
            "ttl": ttl,
            "data_len": data_len,
            "data": data
        }
        # print_RR(record)

        all_additional.append(record)
        i += 1

    return header_info, question_info, all_answers, all_authority, all_additional



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

        label_length = response[index]
        index += 1

        # find the end of domain name and break
        if label_length == 0:
            break

        # for pointers # TODO change to a better if statement (this is like hard coding)
        if label_length == 192:
            index -= 1
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
    #find the domain (could be compressed or not)
    name, new_index = rr_name_finder(response, curr_index)

    #get type and class
    q_type, q_class, new_index = extract_qtype_class(response, new_index)

    #next 4 bytes is ttl 
    ttl = response[new_index: new_index + 4]
    new_index = new_index + 4  #increment to get to data len

    #data len (2 byte)
    data_len = int.from_bytes(response[new_index:new_index + 2], byteorder='big')
    
    new_index = new_index + 2   #increment to get rdata 
    

    # rdata (different for each one)
    if int.from_bytes(q_type, byteorder='big') == 1:
        # A data- A 32 bit Internet address.
        ip_address_raw = response[new_index:new_index + 4]
        data = socket.inet_ntoa(ip_address_raw)
        new_index = new_index + 4

    elif int.from_bytes(q_type, byteorder='big') == 2:
        # NS data 
        data_list = []
        data, new_index, flags = extract_domain_name(response, new_index)
        data_list.append(data)

        if (flags == True):
            # theres additional data thats a pointers
            two_bytes = response[new_index:new_index + 2]

            if (check_pointer(two_bytes) == True):
                #if first two bits are 1s, its a pointer 
                # figure out it's index and pass into domain extractor 

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                data = '.'.join(data_list)

                new_index = new_index + 2

    elif int.from_bytes(q_type, byteorder='big') == 5:
        #CNAME data 

        data_list = []
        data, new_index, flags = extract_domain_name(response, new_index)
        data_list.append(data)

        if (flags == True):
            two_bytes = response[new_index:new_index + 2]
            if (check_pointer(two_bytes) == True):

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                data = '.'.join(data_list)

                new_index = new_index + 2

    else:
        data = bytes_to_ipv6_address(response[new_index:new_index + 16])
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

    if (check_pointer(first_two_bytes) == True):
        data_list = []
        #if first two bits are 1s, its a pointer 
        # figure out it's index and pass into domain extractor 
        as_an_int = int.from_bytes(first_two_bytes, byteorder='big')
        index_number = extractKBits(as_an_int, 14, 0)
        name, new_index, flags = extract_domain_name(response, index_number)

        if (flags == False):
            return_index = curr_index + 2

        #check if return index has 1 as first 2 bits 
        else: 
            data_list.append(name)
            two_bytes = response[new_index:new_index + 2]
            if (check_pointer(two_bytes) == True):
                #if first two bits are 1s, its a pointer 
                # figure out it's index and pass into domain extractor 

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                name = '.'.join(data_list)
                return_index = curr_index + 2

    else:
        data_list = []
        # else, address (use function to decode the rr name)
        name, new_index, flags = extract_domain_name(response, curr_index)
        if (flags == False):
            return_index = new_index

        #check if return index has 1 as first 2 bits 
        else: 
            data_list.append(name)
            two_bytes = response[new_index:new_index + 2]
            if (check_pointer(two_bytes) == True):
                #if first two bits are 1s, its a pointer 
                # figure out it's index and pass into domain extractor 

                as_an_int = int.from_bytes(two_bytes, byteorder='big')
                index_number = extractKBits(as_an_int, 14, 0)
                name_addition, ignore, flags = extract_domain_name(response, index_number)
                data_list.append(name_addition)
                name = '.'.join(data_list)
                return_index = new_index + 2


    return name, return_index


#returns true if response pointer
def check_pointer(first_two_bytes):

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




#PRINTING FUNCTIONS FOR DEBUGGING
def print_header(header_info):
    print("HEADER\n")
    print("TRANSACTION ID:", hex(int.from_bytes(header_info['id'], byteorder='big')), "\t\tFLAGS:", hex(int.from_bytes(header_info['flags'], byteorder='big')))
    print("QUESTIONS:", int.from_bytes(header_info['question'], byteorder='big'), "\tANSWER RRs:", int.from_bytes(header_info['answer'], byteorder='big'), "\tAUTHORITY RRs:", int.from_bytes(header_info['authority_rr'], byteorder='big'), "\tADDITIONAL RRs:", int.from_bytes(header_info['additional_rr'], byteorder='big'))
    print("\n")

def print_question(question_info):
    print("QUESTION SECTION")
    # print(f"DOMAIN NAME: {question_info['domain']}\tQTYPE: {int.from_bytes(question_info['q_type'], byteorder='big')}\tQCLASS: {int.from_bytes(question_info['q_class'], byteorder='big')}\n")
    # print(f"DOMAIN NAME: {question_info['domain']}\tQTYPE: {int.from_bytes(question_info['q_type'], byteorder='big')}\tQCLASS: {int.from_bytes(question_info['q_class'], byteorder='big')}\n")
    print(f"{question_info['domain']}\tQTYPE: ", end="")

    if (int.from_bytes(question_info['q_type'], byteorder='big') == 1):
            print("A", end="")
    elif (int.from_bytes(question_info['q_type'], byteorder='big') == 2):
        print("NS", end="")
    elif (int.from_bytes(question_info['q_type'], byteorder='big') == 5):
        print("CNAME", end = "")
    elif (int.from_bytes(question_info['q_type'], byteorder='big') == 15):
        print("MX", end = "")
        

    print(f"\tQCLASS:", end="") 
    if (int.from_bytes(question_info['q_class'], byteorder='big') == 1):
        print("IN")
    
    print()

def print_RR(rr_info):
    print(f"\t NAME: {rr_info['name']}\tQTYPE: {int.from_bytes(rr_info['q_type'], byteorder='big')}\tQCLASS: {int.from_bytes(rr_info['q_class'], byteorder='big')}\tTTL:{int.from_bytes(rr_info['ttl'], byteorder='big')}\tDATA LENGTH:{rr_info['data_len']}\tRDATA:{rr_info['data']}")

def print_partial_header(header_info):
    print("HEADER")
    print("TRANSACTION ID:", hex(int.from_bytes(header_info['id'], byteorder='big')), "\t\tFLAGS:", hex(int.from_bytes(header_info['flags'], byteorder='big')))
    print("\n")



