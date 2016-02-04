#!/usr/bin/python 

# replihack - A simple python script using nmap for discovering host details
# To do: Pipe results to csv file for each host, improve error handling



# Necessary modules 
import os
import sys
import time
try:
	import nmap
except:
	sys.exit("[!] Oops! Do you have the nmap module installed?: pip install python-nmap")
import csv

#import subprocess
from subprocess import Popen, PIPE
import subprocess
import StringIO

#Still need to verify the Nmap scans we are running need be ran as root. I switched them up from earlier and haven't checked back yet.
if not os.geteuid() == 0:
        sys.exit("Oops. You need to be root! \n")


# Colors for terminal
r = '\033[31m' #red
g = '\033[32m' #green

print ""
print g + "RepliHack - a tool created with Python and Nmap to quickly fingerprint a network "
print ""

print g+ "######################################################"
print "################# USeeUHack ##########################"
print "######################################################"
print ""

#These can probably be moved somewhere else to make the script more effecient
nm = nmap.PortScanner()
nm.all_hosts()
#timeStart = int(time.time())




#creating variables used to output current local IP to user
#eth1 = subprocess.Popen(['/sbin/ifconfig', 'eth0',], stdout=PIPE)
#eth0 = subprocess.Popen(['/sbin/ifconfig', 'eth1',], stdout=PIPE)
#out1, err = eth1.communicate()
#out2, err = eth0.communicate()


f = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
your_ip=f.read()
#print your_ip
print ' Your IP is: ' + your_ip


def main():

    # The main menu
    print r+ "\n * What would you like to do? * \n"
    print " [1] Ping Sweep Network"  
    print " [2] Default SYN Scan" 
    print " [3] Default UDP Scan" 
    print " [4] Service & Version Detection Scan"  
    print " [5] Exit"

    # Ask user to select choice from menu
    option = raw_input("\n [>] Select option from above: ")

    print g+ ""





#Normal Ping scan. Echo request sent. Very likely these requests will be blocked if probing externally. This is just to get a very quick look
    if option == '1':

	# Here we are accessing the variable stored in eth0 and eth1 from 'ifconfig' above and using them to tell the user their current local IP addresses. Have not tested with more than 2 ifaces
        for line in out1.split('\n'):
            line = line.lstrip()
            if line.startswith('inet addr:'):
                ipethzero = line.split()[1][5:]
	        print '\n [>] Your eth0 IP address is {}'.format(ipethzero)
	

        for line in out2.split('\n'):
            line = line.lstrip()
            if line.startswith('inet addr:'):
                ipethone = line.split()[1][5:]
	        print '\n [>] Your eth1 IP address is {}\n'.format(ipethone)



	# Ask the user what network they want to scan and storing that in "hosts" to be later accessed by the "nm.scan" method below
        hosts = raw_input(" [>] Enter network in CIDR notation, eg. 192.168.100.X/24 : ")
	
	#starting our timer

	# Nmap options: -n (no name resolution), -PE is an ICMP Echo Request
        print "\n * Ping sweeping the network ... \n"
	timeStart = int(time.time())
        nm.scan(hosts, arguments='-n -PE')


	
	
 	print"\n   Report: Network Neighbors to {} \n".format(hosts)
	print(' 	   -----------------------------')
	
	timeDone = int(time.time())
        timeRes = timeDone-timeStart


	#creating our list of hosts
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
	
	# For loop to go through each host discovered and print the address of the host and the status. Obviously only the hosts that are up will appear to the user
    	for host, status in hosts_list:
           print('	[>] Host: {0}: State: {1}\n'.format(host, status))

	#Outputs timing stats


        print " [*] Targeted scan completed successfully!\n"
        print ' [*] Scan time (s): ' + str(timeRes)
        main()




    
#Default SYN scan. 
    elif option == '2':
        host = raw_input(" [>] Enter IP address to be scanned: ")
	print "\n * Scanning Top 10 TCP Ports on {} ...  \n".format(host)
	timeStart = int(time.time())

	# Our nmap scan. -sS is our SYS scan. --top-port 10 tells nmap to scan top 10 tcp ports. This is regulary updated via nmap installs. This may break with future versions
	nm.scan(host, arguments='-n -sS --top-ports 10')


timeDone = int(time.time())
        timeRes = timeDone-timeStart

 	print"\n   Report: Top 10 TCP Ports on {} \n".format(host)
	print(' 	-------------------------')
	


	#extracting the protocol from the scan results


	for proto in nm[host].all_protocols():
	    print(' 	Host : %s (%s)' % (host, nm[host].hostname()))
	    
	    lport = nm[host][proto].keys()
	    lport.sort()
	    for port in lport:
	        print(' 	Port : %s\tState : %s' % (port, nm[host][proto][port]['state']))






        print " [*]Targeted scan completed successfully!\n"
        print ' [*] Scan time (s): ' + str(timeRes)
	main()




#Default UDP Scan
    elif option == '3':
        host = raw_input(" [>] Enter IP address to be scanned: ")
	
	#Here we are scanning top 10 UDP ports and trying to make the scan a little faster with the "-T4"
	print "\n * Scanning Top 10 UDP Ports on {} ... \n".format(host)

	timeStart = int(time.time())
        nm.scan(host, arguments='-n -T4 -sU --top-ports 10')



 	print"\n   Report: Top 10 UDP Ports on {} \n".format(host)
	print(' 	-------------------------')
        
	for proto in nm[host].all_protocols():
	    print(' 	Host : %s (%s)' % (host, nm[host].hostname()))
	   

	    lport = nm[host][proto].keys()
	    lport.sort()
	    for port in lport:
	        print(' 	Port : %s\tState : %s' % (port, nm[host][proto][port]['state']))


   


        #Outputs timing stats. This needs to be improved. Once the timer starts, I can't get it to stop and still be accurate. I didn't scan 
	timeDone = int(time.time())
        timeRes = timeDone-timeStart
        print " [*] Targeted scan completed successfully!\n"
        print ' [*] Scan time (s): ' + str(timeRes)
        main()


#Service & Version Detection
    elif option == '4':
        host = raw_input(" [>] Enter IP address to be scanned: ")						
	print "\n * Detecting running services on {}...".format(host)
        timeStart = int(time.time())
        nm.scan(host, arguments='-n -T4 -sV --top-ports 10')


 	print"\n   	Report: Running Network Services {} \n".format(host)
	print(' 	-------------------------------------------------')

	#create our scanner
	myscanner = nm.csv()

	timeDone = int(time.time())
	timeRes = timeDone-timeStart

	#create our buffer to store the output of our results
	f = StringIO.StringIO(myscanner)
	reader = csv.reader(f, delimiter=';')

	#extracting the information we want from the info in the buffer
	for row in reader:
	    print(   "	Host: " + row[0] + " is running " + "" +row[5] + " " +row[8] + " on port " +row[2])


	timeDone = int(time.time())
        timeRes = timeDone-timeStart
        print " [*] Targeted scan completed successfully!\n"
        print ' [*] Scan time (s): ' + str(timeRes)


        main()

#Exit the script
    elif option == '5':
        print "\n[*!*] Quitting [*!*]\n"
        time.sleep(1)
        sys.exit()
    
    #this error handling can certainly be improved. It really only catches errors at the main menu
    else:
	print "\n [*!*] Didn't quite understand, try again ... \n"
        main()

if __name__ == "__main__":
    try:
        main()
        
    except KeyboardInterrupt:
        print g + "\n\n [**] Script has been been stopped. See ya :)"
        print "\n [**] Stopping...  \n"
        time.sleep(2)
        pass




