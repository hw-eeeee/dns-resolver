import socket
import sys

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
    # while 1:
    message, clientAddress = serverSocket.recvfrom(2048)
    #receive data from the client, now we know who we are talking with
    
    print(message)
    # data = message.decode()
    # print("domain name is ",data)
    # modifiedMessage = message.upper()
    #change the case of the message received from client

    # perform dns resolving 
    # dns_resolver

    # serverSocket.sendto(modifiedMessage, clientAddress)
    message = "recieved yoooo" #REPLACE THIS WITH ACTUAL RESPONSE FROM NAME SERVERS 
    serverSocket.sendto(message.encode('utf-8'), clientAddress)

    #send it back to client, need to specify the client address in sendto
    
    serverSocket.close()

if __name__ == '__main__':
    start_server()