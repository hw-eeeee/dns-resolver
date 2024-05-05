# DNS Resolver

Usage: client resolver_ip resolver_port name [timeout=<timeout>] [type=<record_type>]

## Instructions
STEP 1: 
Start the DNS Resolver: Run resolver.py and specify the port number on which it will listen. For example, to start the resolver on port 5300, use the following command:

`python3 resolver.py 5300`

STEP 2:
Query the DNS Resolver: Use client.py to send a DNS query. You must specify the IP address of the DNS resolver, the port number, and the domain name you want to resolve. 

For example, to query the DNS resolver running on 127.0.0.1 at port 5300 for the domain www.example.com, you can use:
`python3 client.py 127.0.0.1 5300 www.example.com`

To specify a timeout of 10 seconds and request an MX record, use:
`python3 client.py 127.0.0.1 5300 www.example.com timeout=10 type=MX`

