def extract_answer_section(dns_response, answer_section_start, num_answers):
    # Start at the beginning of the answer section
    index = answer_section_start

    # Create a list to store the extracted information for each resource record
    answer_records = []

    # Loop through the answer section and extract the information for each resource record
    for _ in range(num_answers):
        # Read the pointer (2 bytes) to get the domain name
        pointer = dns_response[index : index + 2]
        domain_name = extract_domain_name(dns_response, int.from_bytes(pointer, byteorder='big'))

        # Move the index forward to the type field
        index += 2

        # Read the type (2 bytes) and class (2 bytes)
        rr_type = dns_response[index : index + 2]
        rr_class = dns_response[index + 2 : index + 4]

        # Move the index forward to the TTL field
        index += 4

        # Read the TTL (4 bytes) and data length (2 bytes)
        ttl = int.from_bytes(dns_response[index : index + 4], byteorder='big')
        data_length = int.from_bytes(dns_response[index + 4 : index + 6], byteorder='big')

        # Move the index forward to the data field
        index += 6

        # Read the data based on the type (A or AAAA)
        data = dns_response[index : index + data_length]
        if rr_type == b'\x00\x01':  # A record (IPv4 address)
            ip_address = '.'.join(str(byte) for byte in data)
        elif rr_type == b'\x00\x1c':  # AAAA record (IPv6 address)
            ip_address = ':'.join(f"{byte:02x}{dns_response[index + i + 1]:02x}" for i, byte in enumerate(data[::2]))
        else:
            ip_address = "Unknown data type"  # Handling other data types

        # Store the extracted information as a tuple and append it to the answer_records list
        answer_record = (domain_name, rr_type, rr_class, ttl, ip_address)
        answer_records.append(answer_record)

        # Move the index forward to the start of the next resource record
        index += data_length

    return answer_records

def extract_domain_name(dns_response, start_index):
    # Start reading the domain name at the specified index
    index = start_index
    domain_name_parts = []

    while index < len(dns_response):
        # Read the length of the label
        label_length = dns_response[index]
        index += 1

        if label_length == 0:
            # End of the domain name (null label)
            break

        if (label_length & 0xC0) == 0xC0:
            # Pointer (compression) encountered
            pointer_offset = ((label_length & 0x3F) << 8) + dns_response[index]
            return extract_domain_name(dns_response, pointer_offset)

        # Check if the index is within the valid range
        if index + label_length > len(dns_response):
            raise ValueError("Invalid DNS response format: domain name exceeds buffer length")

        # Read the label and append it to the list of domain name parts
        label = dns_response[index : index + label_length].decode('utf-8')
        domain_name_parts.append(label)
        index += label_length

    # Join the domain name parts with dots to form the complete domain name
    domain_name = '.'.join(domain_name_parts)
    return domain_name


# Example usage with the provided DNS response and starting index of the answer section:
dns_response = b'\x137\x81\x80\x00\x01\x00\x02\x00\x00\x00\x01\x03www\x05koala\x03com\x02au\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01,\x00\x04h\x15-\xd2\xc0\x0c\x00\x01\x00\x01\x00\x00\x01,\x00\x04\xacC\xdb.\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
answer_section_start = 31  # Index where the answer section starts
num_answers = 2  # Number of answer records in the answer section

answer_records = extract_answer_section(dns_response, answer_section_start, num_answers)

# Print the extracted information for each resource record in the answer section
for i, record in enumerate(answer_records):
    domain_name, rr_type, rr_class, ttl, ip_address = record
    print(f"Answer {i + 1}:")
    print("Domain name:", domain_name)
    print("Resource Record type:", rr_type)
    print("Resource Record class:", rr_class)
    print("TTL:", ttl)
    print("IP Address:", ip_address)
    print()
