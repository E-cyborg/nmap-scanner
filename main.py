import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
ip_addr = str(ip_addr)  
print("The IP you entered is: ", ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan \n""")
print("You have selected option: ", resp)

resp_dict = {'1': ['-v -sS', 'tcp'], '2': ['-v -sU', 'udp'], '3': ['-v -sS -sV -sC -A -O', 'tcp']}

if resp not in resp_dict:
    print("Enter a valid option")
else:
    try:
        print("nmap version: ", scanner.nmap_version())
        scanner.scan(ip_addr, "1-1024", resp_dict[resp][0])  

        if scanner[ip_addr].state() == 'up':
            print("Scanner Status: ", scanner[ip_addr].state())
            print("All Protocols: ", scanner[ip_addr].all_protocols())

            open_ports = scanner[ip_addr][resp_dict[resp][1]].keys()
            if open_ports:
                print("Open Ports: ", ', '.join(map(str, open_ports)))
            else:
                print("No open ports found.")
        else:
            print("Host is down.")
    except Exception as e:
        print(f"An error occurred: {e}")
