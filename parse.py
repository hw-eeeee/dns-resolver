import socket
import sys
import random
import struct


def decode_response(returnedMessage):
    print(returnedMessage)
    #HEADER SECTION
    id, flags, question, answer, authority_rr, additional_rr = extract_header(returnedMessage[:12])
    print_header(id, flags, question, answer, authority_rr, additional_rr)

    #QUESTION SECTION 
    # domain_name, q_type, q_class = extract_question_section(returnedMessage)
    domain, q_type, q_class, new_index = extract_question_section(returnedMessage)
    print_question(domain, q_type, q_class)

    #RESOURCE RECORDS
    #answer section
    # for i in range(int.from_bytes(answer, byteorder='big')):
    #     extract_resource_record(returnedMessage[new_index:])
    # print(returnedMessage[new_index:])
    # extract_resource_record(returnedMessage[new_index:], returnedMessage, new_index)




    # if (int.from_bytes(answer, byteorder='big') > 0):
    print_answer_section(returnedMessage, int.from_bytes(answer, byteorder='big'))

    #query domain name- while before '\x00'
    domain_name, curr_index = extract_domain_name(returnedMessage)
    # print("Domain Name:", domain_name, '\n')

    #rest is the answer section (could be more than 1)
    no_of_answers = int.from_bytes(answer, byteorder='big')
    answer_records = extract_answer_section(returnedMessage, curr_index, no_of_answers)


    # extract elements from answer_records 
    for i, record in enumerate(answer_records):
        rr_type, rr_class, ttl, data_length, ip_address = record
        print(f"Answer {i + 1}:")
        print("Domain name:", domain_name)
        print("Resource Record type:", rr_type)
        print("Resource Record class:", rr_class)
        print("TTL:", ttl)
        print("Data Length:", data_length)
        print("IP Address:", ip_address)
        print()





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
    domain, index = extract_domain_name(response)
    q_type, q_class, index = extract_qtype_class(response, index)

    #q type (2 octet) (2, 8 bits) (2 bytes), index_count increment 
    # q_type = response[index:index+2]
    # index+=2

    # #q class (2 octet), index_count increment 
    # q_class = response[index:index+2]
    # index+=2

    return domain, q_type, q_class, index

def extract_qtype_class(response, index):
    q_type = response[index:index+2]
    index+=2

    #q class (2 octet), index_count increment 
    q_class = response[index:index+2]
    index+=2

    return q_type, q_class, index

#extracts domain name from server response
def extract_domain_name(response):
    index = 12
    domain_name_parts = []

    #loop through response
    while True:
        label_length = response[index]
        index += 1

        # find the end of domain name and break
        if label_length == 0:
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










# RESOURCE RECORDS
def extract_resource_record(sliced_response, full_response, curr_index):
    print("RRS RECORDS")
    domain, index = extract_domain_name(sliced_response)
    print("    DOMAIN NAME:", domain)
    # print(full_response[index + curr_index:])
    new_index = index + curr_index
    print(full_response[new_index:])

    # print(new_index, 'NEW INDEX NUMBER')
    # find closest multiple of 4 
    new_index = closest_multiple_of_4(new_index)
    print('NEW INDEX IS', new_index)
    print(full_response[new_index:])
    q_type, q_class, index = extract_qtype_class(full_response, new_index)
    # print("actual new index is", new_index)
    # new_index = 76

    #q type (2 octet) (2, 8 bits) (2 bytes), index_count increment 
    # q_type = full_response[new_index:new_index+2]
    # new_index+=2

    # #q class (2 octet), index_count increment 
    # q_class = full_response[new_index:new_index+2]
    # new_index+=2


    # print("    DOMAIN NAME:", domain)
    print("    QTYPE:", int.from_bytes(q_type, byteorder='big'))
    # print(q_type)
    print("    QCLASS:", int.from_bytes(q_class, byteorder='big'))
    # print(q_class)


def closest_multiple_of_4(n):
    if (n % 4):
        n = n + (4 - n % 4)
        return n









def print_answer_section(returnedMessage, no_of_answers):
    #query domain name- while before '\x00'
    domain_name, curr_index = extract_domain_name(returnedMessage)
    # print("Domain Name:", domain_name, '\n')

    #rest is the answer section (could be more than 1)
    # no_of_answers = int.from_bytes(answer, byteorder='big')
    answer_records = extract_answer_section(returnedMessage, curr_index, no_of_answers)


    # extract elements from answer_records 
    for i, record in enumerate(answer_records):
        rr_type, rr_class, ttl, data_length, ip_address = record
        print(f"Answer {i + 1}:")
        print("Domain name:", domain_name)
        print("Resource Record type:", rr_type)
        print("Resource Record class:", rr_class)
        print("TTL:", ttl)
        print("Data Length:", data_length)
        print("IP Address:", ip_address)
        print()



#edit this!!!
def extract_answer_section(dns_response, answer_section_start, num_answers):
    # Start at the beginning of the answer section
    index = answer_section_start
    index = loop_to_new_index(index, dns_response)

    
    #list to store the extracted information for each resource record
    answer_records = []
    total_ans_count = 0
    while (total_ans_count < num_answers):
        #get the record type
        rr_type = int.from_bytes(dns_response[index:index + 2], byteorder='big')
        print("rr type is" , rr_type)
        index+=2 #increment to get rr_class

        #get the Resource Record Class
        rr_type_class = int.from_bytes(dns_response[index:index + 2], byteorder='big')
        print("rr class is" , rr_type_class) #increment to ttl 
        index+=2 #increment to ttl 

        #get the ttl 
        ttl_value = int.from_bytes(dns_response[index:index + 4], byteorder='big')
        print("ttl_value is ", ttl_value)
        # print("ttl_value is without formatting", ttl_value)
        index+=4 #increment to data length 

        #get data length 
        data_length_value = int.from_bytes(dns_response[index:index + 2], byteorder='big')
        print("data_length_value is ", data_length_value)
        index+=2 #increment to IP address

        #get ip address
        #if A type record, Ip address is 4 bytes 
        if (rr_type == 1): #TODO LATER
            ip_address_raw = dns_response[index: index + 4]
            print('RAW IS', ip_address_raw)
            ip_address = socket.inet_ntoa(ip_address_raw)
            print("ip_address is ", ip_address)

        #if AAAA type, IP address is 16 bytes


        total_ans_count+=1
        index = loop_to_new_index(index, dns_response)
        # print("next answer section", dns_response[index:], '\n')

        # Store the extracted information as a tuple and append it to the answer_records list
        answer_record = (rr_type, rr_type_class, ttl_value, data_length_value, ip_address)
        answer_records.append(answer_record)

    return answer_records



def loop_to_new_index(index, dns_response):
    answer = dns_response[index:]
    #loop until we see '\xc0\x0c'
    i = 0
    while (i < len(answer) - 1):
        # print(answer[i], "and ", answer[i + 1])
        if (answer[i] == 192 and answer[i + 1] == 12):
            break
        i+=1
    
    index += i + 2

    return index
