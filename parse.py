import socket
import sys
import random
import struct


def decode_response(returnedMessage):
    # print(returnedMessage)
    #HEADER SECTION
    id, flags, question, answer, authority_rr, additional_rr = extract_header(returnedMessage[:12])
    print_header(id, flags, question, answer, authority_rr, additional_rr)

    #QUESTION SECTION 
    domain, q_type, q_class, new_index = extract_question_section(returnedMessage)
    print_question(domain, q_type, q_class)


    #RESOURCE RECORDS
    # answer ones 
    print("ANSWERS")
    i = 0
    while i < int.from_bytes(answer, byteorder='big'):
        print(f"Answer {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        i += 1
    
    # authority ones 
    print("AUTHORITY")
    i = 0
    while i < int.from_bytes(authority_rr, byteorder='big'):
        print(f"Answer {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        i += 1
    
    print("ADDITIONAL")
    i = 0
    while i < int.from_bytes(additional_rr, byteorder='big'):
        print(f"Answer {i + 1}:")
        name, q_type, q_class, ttl, data_len, data, new_index = extract_resource_record(returnedMessage, new_index)
        i += 1



#HEADER SECTION
def extract_header(response):
    
    id = response[:2]               # id: first 16 bits (2 bytes) 
    flags = response[2:4]           # flags next 16 bits
    question = response[4:6]        # question count next 16 bits 
    answer = response[6:8]          # answer count next 16 bits 
    authority_rr = response[8:10]   # authority rr count next 16 bits  
    additional_rr = response[10:12] # additional rr count next 16 bits

    return id, flags, question, answer, authority_rr, additional_rr


def print_header(id, flags, question, answer, authority_rr, additional_rr):
    print("HEADER")
    print("    TRANSACTION ID:", hex(int.from_bytes(id, byteorder='big')))
    print("    FLAGS:", hex(int.from_bytes(flags, byteorder='big')))
    print("    QUESTIONS:", int.from_bytes(question, byteorder='big'))
    print("    ANSWER RRs:", int.from_bytes(answer, byteorder='big'))
    print("    AUTHORITY RRs:", int.from_bytes(authority_rr, byteorder='big'))
    print("    ADDITIONAL RRs:", int.from_bytes(additional_rr, byteorder='big'))
    print()





#QUESTION SECTION
def extract_question_section(response):
    domain, index = extract_domain_name(response, 12)
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
    index = starting_index
    domain_name_parts = []
    # print(response)
    # print("response length is", len(response))
    # print("index is", index)

    #loop through response
    while True:
        label_length = response[index]
        # print(label_length)
        index += 1

        # find the end of domain name and break
        if label_length == 0:
            break

        # for pointers 
        if label_length == 192:
            # print('HIIIIIIIIIII')
            break

        # Read the label itself and append it to the list of domain name parts
        label = response[index : index + label_length].decode('utf-8')
        domain_name_parts.append(label)
        index += label_length

    # join domain name
    domain_name = '.'.join(domain_name_parts)
    
    return domain_name, index

def print_question(domain, q_type, q_class):
    print("QUESTION")
    print("    DOMAIN NAME:", domain)
    print("    QTYPE:", int.from_bytes(q_type, byteorder='big'))
    print("    QCLASS:", int.from_bytes(q_class, byteorder='big'))
    print()







# RESOURCE RECORDS
def extract_resource_record(response, curr_index):
    # print("RRS RECORDS")
    #find the domain (could be compressed or not)
    name, new_index = rr_name_finder(response, curr_index)
    print("    NAME:", name)
    # print("update1:", new_index)


    #get type and class
    q_type, q_class, new_index = extract_qtype_class(response, new_index)
    print("    QTYPE:", int.from_bytes(q_type, byteorder='big'))
    print("    QCLASS:", int.from_bytes(q_class, byteorder='big'))
    # print("update 2:", new_index)

    #next 4 bytes is ttl 
    ttl = response[new_index: new_index + 4]
    new_index = new_index + 4  #increment to get to data len
    print("    TTL:", int.from_bytes(ttl, byteorder='big'))

    #data len (2 byte)
    # data_len = response[new_index: new_index + 2]
    data_len = int.from_bytes(response[new_index:new_index + 2], byteorder='big')
    print("    DATA LENGTH:", data_len)
    new_index = new_index + 2   #increment to get rdata 

    # rdata (different for each one)
    if int.from_bytes(q_type, byteorder='big') == 1:
        # A data- A 32 bit Internet address.
        ip_address_raw = response[new_index:new_index + 4]
        data = socket.inet_ntoa(ip_address_raw)

        new_index = new_index + 4

    elif int.from_bytes(q_type, byteorder='big') == 2:
        # NS data 
        data, new_index = extract_domain_name(response, new_index)

    elif int.from_bytes(q_type, byteorder='big') == 5:
        #CNAME data 
        data, new_index = extract_domain_name(response, new_index)

    print("    RDATA:", data)

    return name, q_type, q_class, ttl, data_len, data, new_index
    

def rr_name_finder(response, curr_index):
    #    - a sequence of labels ending in a zero octet (normal address)
    #    - a pointer
    #    - a sequence of labels ending with a pointer


    # - a pointer
    # (check first 2 bits of response)
    first_two_bytes = response[curr_index:curr_index + 2]

    if (check_pointer(first_two_bytes) == True):
        #if first two bits are 1s, its a pointer 
        # figure out it's index and pass into domain extractor 

        as_an_int = int.from_bytes(first_two_bytes, byteorder='big')
        index_number = extractKBits(as_an_int, 14, 0)
        name, ignore = extract_domain_name(response, index_number)
        # print(name)
        return_index = curr_index + 2
        # print(curr_index)
        # print(response[return_index:])
        # print(response[curr_index:curr_index + 2])

    else:
        # else, address (use function to decode the rr name)
        name, new_index = extract_domain_name(response, index_number)
        return_index = new_index
        print("WTF")



    return name, return_index

#returns true if response pointer
def check_pointer(first_two_bytes):
    # print("first two bytes", first_two_bytes)

    #check if first 2 bits is 1 and 1 
    as_an_int = int.from_bytes(first_two_bytes, byteorder='big')

    if (extractKBits(as_an_int, 1, 16) == 1) and (extractKBits(as_an_int, 1, 15) ==1):
        # print("both ")
        return True

    return False


def extractKBits(num,k,p):
 
     # convert number into binary first
     binary = bin(num)
    #  print(binary)
 
     # remove first two characters
     binary = binary[2:]
 
     end = len(binary) - p
     start = end - k + 1
 
     # extract k  bit sub-string
     kBitSubStr = binary[start : end+1]
 
     # convert extracted sub-string into decimal again
     return (int(kBitSubStr,2))


#BELOW THIS IS WTF!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


# def print_answer_section(returnedMessage, no_of_answers):
#     #query domain name- while before '\x00'
#     domain_name, curr_index = extract_domain_name(returnedMessage)
#     # print("Domain Name:", domain_name, '\n')

#     #rest is the answer section (could be more than 1)
#     # no_of_answers = int.from_bytes(answer, byteorder='big')
#     answer_records = extract_answer_section(returnedMessage, curr_index, no_of_answers)


#     # extract elements from answer_records 
#     for i, record in enumerate(answer_records):
#         rr_type, rr_class, ttl, data_length, ip_address = record
#         print(f"Answer {i + 1}:")
#         print("Domain name:", domain_name)
#         print("Resource Record type:", rr_type)
#         print("Resource Record class:", rr_class)
#         print("TTL:", ttl)
#         print("Data Length:", data_length)
#         print("IP Address:", ip_address)
#         print()



# #edit this!!!
# def extract_answer_section(dns_response, answer_section_start, num_answers):
#     # Start at the beginning of the answer section
#     index = answer_section_start
#     index = loop_to_new_index(index, dns_response)

#     print()
#     print(dns_response[answer_section_start: answer_section_start +2])

    
#     #list to store the extracted information for each resource record
#     answer_records = []
#     total_ans_count = 0
#     while (total_ans_count < num_answers):
#         #get the record type
#         rr_type = int.from_bytes(dns_response[index:index + 2], byteorder='big')
#         print("rr type is" , rr_type)
#         index+=2 #increment to get rr_class

#         #get the Resource Record Class
#         rr_type_class = int.from_bytes(dns_response[index:index + 2], byteorder='big')
#         print("rr class is" , rr_type_class) #increment to ttl 
#         index+=2 #increment to ttl 

#         #get the ttl 
#         ttl_value = int.from_bytes(dns_response[index:index + 4], byteorder='big')
#         print("ttl_value is ", ttl_value)
#         # print("ttl_value is without formatting", ttl_value)
#         index+=4 #increment to data length 

#         #get data length 
#         data_length_value = int.from_bytes(dns_response[index:index + 2], byteorder='big')
#         print("data_length_value is ", data_length_value)
#         index+=2 #increment to IP address

#         #get ip address
#         #if A type record, Ip address is 4 bytes 
#         if (rr_type == 1): #TODO LATER
#             ip_address_raw = dns_response[index: index + 4]
#             print('RAW IS', ip_address_raw)
#             ip_address = socket.inet_ntoa(ip_address_raw)
#             print("ip_address is ", ip_address)

#         #if AAAA type, IP address is 16 bytes


#         #if CNAME type, get CNAME
#         print(dns_response[index:])
#         if (rr_type == 5):
#             #CNAME (get domain name format)
#             print('STARTING INDEX number', dns_response[index])

#             domain, index_additional = extract_domain_without_index(dns_response[index:])
#             print("CNAME IS", domain)
#             index = index + index_additional

#             print("new index is", index)
#             print("remaining data is ", dns_response[index:])

#         total_ans_count+=1
#         index = loop_to_new_index(index, dns_response)
#         # print("next answer section", dns_response[index:], '\n')

#         # Store the extracted information as a tuple and append it to the answer_records list
#         answer_record = (rr_type, rr_type_class, ttl_value, data_length_value, ip_address)
#         answer_records.append(answer_record)

#     return answer_records

# def extract_domain_without_index(response):
#     index = 0
#     domain_name_parts = []

#     while True:
#         label_length = response[index]
#         index += 1

#         # find the end of domain name and break
#         if label_length == 0:
#             break

#         # Read the label itself and append it to the list of domain name parts
#         label = response[index : index + label_length].decode('utf-8')
#         domain_name_parts.append(label)
#         index += label_length

#     # join domain name
#     domain_name = '.'.join(domain_name_parts)
    
#     return domain_name, index

# def loop_to_new_index(index, dns_response):
#     answer = dns_response[index:]
#     #loop until we see '\xc0\x0c'
#     i = 0
#     while (i < len(answer) - 1):
#         # print(answer[i], "and ", answer[i + 1])
#         if (answer[i] == 192 and answer[i + 1] == 12):
#             break
#         i+=1
    
#     index += i + 2

#     return index
