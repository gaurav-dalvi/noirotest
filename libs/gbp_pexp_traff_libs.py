#!/usr/bin/env python
import pexpect
import sys
import re
from time import sleep
from testcases.config import conf

class gbpExpTraff(object):
   
    def __init__(self,net_node_ip,netns,src_vm_ip,dst_vm_ip):
        """
        ::pkt_size, if set to JUMBO we will send out 9000
        """
        self.net_node = net_node_ip
        self.netns = netns
        self.src_ep = src_vm_ip
        self.dest_ep = dst_vm_ip
        if not isinstance(self.dest_ep,list):
           self.dest_ep = [self.dest_ep]
        self.pkt_cnt = 3
        self.vm_user = conf['image_user']
        self.vm_password = conf['image_password']
        self.vm_prompt = conf['image_prompt']
        self.host_prompt = '#'

    def ssh_to_compute_host(self):
        pexpect_session = pexpect.spawn('ssh root@%s' %(self.net_node))
        pexpect_session.expect(self.host_prompt) #Expecting passwordless access
        pexpect_session.sendline('hostname')
        pexpect_session.expect(self.host_prompt)
        print pexpect_session.before
        return pexpect_session

    def vm_reachable(self, pexpect_session):
        pexpect_session.sendline('ip netns exec %s ping %s -c 2' \
			%(self.netns,self.src_ep)) ## Check whether ping works first
        pexpect_session.expect(self.host_prompt)
        print pexpect_session.before
        print 'Out ==NOIRO'
        if len(re.findall('100% packet loss',pexpect_session.before)): #Count of ping pkts
           print "Cannot run any traffic test since Source VM is Unreachable"
           return 2
        return 0

    def parse_ping_output(self,out,pkt_cnt):
        cnt = pkt_cnt
        output = out
        check = re.search('\\b%s\\b packets transmitted, \\b(\d+)\\b packets received' %(cnt),output,re.I)
        if check != None:
           if int(cnt) - int(check.group(1)) > 1:
              return 0
        else:
            return 0
        return 1

    def vm_ssh_login(self, pexpect_session):
        login_retry = 1

        while login_retry < 4: 
            try:
		print "Trying to SSH into VM ....."
                pexpect_session.sendline('ip netns exec %s ssh %s@%s' \
				%(self.netns,self.vm_user,self.src_ep))
                ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
                i = pexpect_session.expect([ssh_newkey,'password:',pexpect.EOF])
                if i == 0:
                    pexpect_session.sendline('yes')
                    i = pexpect_session.expect([ssh_newkey,'password:',pexpect.EOF])
                if i == 1:
                    pexpect_session.sendline(self.vm_password)
                pexpect_session.expect('\$')
                break
            except Exception as e:
		if login_retry == 3:
                    print "After 3 attempts Failed to SSH into the VM from the Namespace\n"
                    print "\nException Error: %s\n" %(e)
		    return 2
            sleep(10)
            login_retry +=1
        return 0

    def vm_sudo(self, pexpect_session):
        pexpect_session.sendline('sudo -s')
        userstring = self.vm_user + ':'
        pexpect_session.expect(userstring)
        pexpect_session.sendline(self.vm_password)
        pexpect_session.expect(self.vm_prompt)

    def vm_test_traffic(self, pexpect_session, protocols, tcp_syn_only=0):
        results = {}
        for dest_ep in self.dest_ep:
            results[dest_ep] = {'icmp':'NA', 'tcp':'NA', 'udp':'NA'} #Setting results for all proto = NA, assuming no traffic is not tested for the specific proto
            for protocol in protocols:
                if protocol=='icmp' or protocol=='all':
                   pexpect_session.sendline('hping3 %s --icmp -c %s --fast -q -d %s' \
				%(dest_ep,self.pkt_cnt,self.pkt_size))
                   pexpect_session.expect(self.vm_prompt)
                   print "Sent ICMP packets"
                   result=pexpect_session.before
                   print result
                   if self.parse_ping_output(result,self.pkt_cnt) !=0:
                      results[dest_ep]['icmp']=1
                   else:
                      results[dest_ep]['icmp']=0
                if protocol=='tcp'or protocol=='all':
                   cmd_s = "sudo hping3 %s -S -V -p %s -c %s --fast -q" \
			    %(dest_ep,port,self.pkt_cnt)
                   cmd_sa = "sudo hping3 %s -S -A -V -p %s -c %s --fast -q" \
			    %(dest_ep,port,self.pkt_cnt)
                   cmd_saf = "sudo hping3 %s -S -A -F -V -p %s -c %s --fast -q" \
			    %(dest_ep,port,self.pkt_cnt)
                   if not tcp_syn_only:
                      for cmd in [cmd_s,cmd_sa,cmd_saf]:
                         pexpect_session.sendline(cmd)
                         pexpect_session.expect(self.vm_prompt)
                         print "Sent TCP SYN,SYN ACK,SYN-ACK-FIN to %s" \
				%(dest_ep)
                         result=pexpect_session.before
                         print result
                         if self.parse_ping_output(result,self.pkt_cnt) !=0:
                            results[dest_ep]['tcp']=1
                         else:
                            results[dest_ep]['tcp']=0
                   else:
		        #Over-riding the label cmd_s,to run simple ncat
	                cmd_s = "nc -w 1 -v %s -z 22" %(dest_ep)
                        pexpect_session.sendline(cmd_s)
                        pexpect_session.expect(self.vm_prompt)
                        result=pexpect_session.before
			print result
                        if 'succeeded' in result:
                            results[dest_ep]['tcp']=1
                        else:
                            results[dest_ep]['tcp']=0
                if protocol=='udp' or protocol=='all':
                    cmd = "hping3 %s --udp -p %s -c %s --fast -q" %(dest_ep,port,self.pkt_cnt)
                    pexpect_session.sendline(cmd)
                    pexpect_session.expect(self.vm_prompt)
                    print 'Sent UDP packets'
                    result=pexpect_session.before
                    print result
                    if self.parse_ping_output(result,self.pkt_cnt) !=0:
                        results[dest_ep]['udp']=1
                    else:
                        results[dest_ep]['udp']=0
        return results 

    def vm_start_http_server(self, pexpect_session):
	pexpect_session.sendline('nohup python -m SimpleHTTPServer 80 &')
	pexpect_session.expect(self.vm_prompt)

    def vm_stop_http_server(self, pexpect_session):
        print "Stopping SimpleHTTPServer on port 80"
        nc_cmd = """ps -ef | grep [S]imple | awk -F" " '{print $1}'"""
	pexpect_session.sendline(nc_cmd)
	pexpect_session.expect(self.vm_prompt)
        nc_pid=pexpect_session.before
        kill_cmd = 'kill %s' % nc_pid
        pexpect_session.sendline(kill_cmd)
        pexpect_session.expect(self.vm_prompt)

    def test_run(self,
                 protocols=['icmp','tcp','udp'],
                 port=80,tcp_syn_only=0,
                 jumbo=0):
        pexpect_session = self.ssh_to_compute_host()

        if self.vm_reachable(pexpect_session):
            return 2
        if self.vm_ssh_login(pexpect_session):
            return 2

        self.vm_sudo(pexpect_session)
        self.vm_start_http_server(pexpect_session)
        pexpect_session.sendline('ip addr show eth0')
        pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before

	while False: #TODO: Unless the inherent metadata issue is resolved, no point in executing this part of the code
	    pexpect_session.sendline('curl http://169.254.169.254/latest/meta-data')
	    pexpect_session.expect(self.vm_prompt)
	    meta_result = pexpect_session.before
	    print meta_result
	    if 'hostname' in pexpect_session.before:
	        results['metadata']=1
	    else:
	        results['metadata']=0
        if jumbo == 1:
           self.pkt_size = 9000
        else:
           self.pkt_size = 1000

        result = self.vm_test_traffic(pexpect_session, protocols, tcp_syn_only=tcp_syn_only)
        self.vm_stop_http_server(pexpect_session)
        return result


    def run_and_verify_traffic(self,proto,traff_results='',
			       tcp_syn_only=0,jumbo=0
				):
	# This method just verify the traffic results
	# OR
	# Can be used to send traffic and verify the results

	if traff_results:
            print 'Traffic Results to be analysed == %s' %(traff_results)
	    results = traff_results
	else:
	    print 'Run Traffic for the Protocols: %s and then analyze results' %(proto)
	    results = self.test_run(protocols=proto,tcp_syn_only=tcp_syn_only,jumbo=jumbo)
        if results == 2:
            return 0
	for dest_ip in self.dest_ep:
            allow_list = proto
            failed = {key: val for key, val in results[
                dest_ip].iteritems() if val == 0 and key in allow_list}
            failed.update({key: val for key, val in results[
                          dest_ip].iteritems() if val == 1 and key not in allow_list})
        if len(failed) > 0:
                print 'Following traffic_types %s = Failed' %(failed)
                return 0
        else:
                return 1
	
    def aap_traff(self,aap_ip):
	"""
	aap_ip :: should be ip address of AAP with mask
		  eg: 1.1.1.1/24
	"""
        pexpect_session = pexpect.spawn('ssh root@%s' %(self.net_node))
        pexpect_session.expect(self.vm_prompt) #Expecting passwordless access
        pexpect_session.sendline('hostname')
        pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before
        pexpect_session.sendline('ip netns exec %s ping %s -c 2' %(self.netns,self.src_ep)) ## Check whether ping works first
        pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before
        if len(re.findall('100% packet loss',pexpect_session.before)): #Count of ping pkts
           print "Cannot run any traffic test since Source VM is Unreachable"
           return 0
	pkg = 'iputils-arping_20121221-4ubuntu1_amd64.deb'
        scp_retry = 1
        while scp_retry < 4: 
            try:
		print "SecureCopy the Arping-tool into VM"
                pexpect_session.sendline('ip netns exec %s scp %s %s@%s:'
                    %(self.netns, self.vm_user,pkg,self.src_ep))
                ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
                i = pexpect_session.expect([ssh_newkey,'password:',pexpect.EOF])
                if i == 0:
                    pexpect_session.sendline('yes')
                    i = pexpect_session.expect([ssh_newkey,'password:',pexpect.EOF])
                if i == 1:
                    pexpect_session.sendline(self.vm_password)
                pexpect_session.expect(self.vm_prompt)
		print "Trying to SSH into VM ....."
                pexpect_session.sendline('ip netns exec %s ssh %s@%s' \
			    %(self.netns,self.vm_user,self.src_ep))
		pexpect_session.expect('password:')
		pexpect_session.sendline(self.vm_password)
		pexpect_session.expect('\$')
                break
            except Exception as e:
		if scp_retry == 3:
                    print "After 3 attempts Failed to SecureCopy/Login into VM from Namespace\n"
                    print "\nException Error: %s\n" %(e)
		    return 0
            sleep(10)
            scp_retry +=1
        pexpect_session.sendline('sudo -s')
        userstring = self.vm_user + ':'
        pexpect_session.expect(userstring)
        pexpect_session.sendline(self.vm_password)
        pexpect_session.expect(self.vm_prompt)
	pexpect_session.sendline('dpkg -i %s ' %(pkg))
	pexpect_session.expect(self.vm_prompt)
        pexpect_session.sendline('ip addr show eth0')
        pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before
	pexpect_session.sendline('ip addr add %s dev eth0' %(aap_ip))
	pexpect_session.expect(self.vm_prompt)
	print "After adding the AAP-IP to the VM port"
        pexpect_session.sendline('ip addr show eth0')
        pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before
	print "Send arping now ...."
	pexpect_session.sendline('arping -c 4 -A -I eth0 %s' %(aap_ip.rstrip('/24')))
	pexpect_session.expect(self.vm_prompt)
        print pexpect_session.before
	return 1


class gbpExpTraffNoHping3(gbpExpTraff):

    def vm_sudo(self, pexpect_session):
        print "Entering sudo priviledged command mode"
        pexpect_session.sendline('sudo -s')
        pexpect_session.expect(self.vm_prompt)

    def vm_start_http_server(self, pexpect_session):
        print "Starting netcat session on port 80"
        nc_cmd = 'nc -p 80 -n -lk -e '
        http_server_cmd = """'echo -e Hi!'"""
        cmdstring = nc_cmd + http_server_cmd + "&"
        print "HTTP server command is: " + cmdstring
	pexpect_session.sendline(cmdstring)
	pexpect_session.expect(self.vm_prompt)

    def vm_stop_http_server(self, pexpect_session):
        print "Stopping netcat session on port 80"
        nc_cmd = """ps -ef | grep [n]c | awk -F" " '{print $1}'"""
	pexpect_session.sendline(nc_cmd)
	pexpect_session.expect(self.vm_prompt)
        nc_pid=pexpect_session.before
        kill_cmd = 'kill %s' % nc_pid
        pexpect_session.sendline(kill_cmd)
        pexpect_session.expect(self.vm_prompt)

    def vm_test_traffic(self, pexpect_session, protocols, tcp_syn_only=0):
        results = {}
        for dest_ep in self.dest_ep:
            results[dest_ep] = {'icmp':'NA', 'tcp':'NA', 'udp':'NA'} #Setting results for all proto = NA, assuming no traffic is not tested for the specific proto
            for protocol in protocols:
                if protocol=='icmp' or protocol=='all':
                   ping_command = 'ping %s -c %s -s %s' % (dest_ep,
                                                           self.pkt_cnt,
                                                           self.pkt_size)
                   print "ping command: " + ping_command
                   pexpect_session.sendline(ping_command)
                   pexpect_session.expect(self.vm_prompt)
                   print "Sent ICMP packets"
                   result=pexpect_session.before
                   print "ICMP result: " + result
                   if self.parse_ping_output(result,self.pkt_cnt) !=0:
                      results[dest_ep]['icmp']=1
                   else:
                      results[dest_ep]['icmp']=0
                if protocol=='tcp'or protocol=='all':
		    #Over-riding the label cmd_s,to run simple ncat
	            cmd_s = "nc -w 1 -v %s -z 22" %(dest_ep)
                    pexpect_session.sendline(cmd_s)
                    pexpect_session.expect(self.vm_prompt)
                    result=pexpect_session.before
                    print "TCP result: " + result
                    if 'open' in result:
                        results[dest_ep]['tcp']=1
                    else:
                        results[dest_ep]['tcp']=0
                if protocol=='udp' or protocol=='all':
	            cmd = "nc -w 1 -v %s -u -z 22" %(dest_ep)
                    pexpect_session.sendline(cmd)
                    pexpect_session.expect(self.vm_prompt)
                    print 'Sent UDP packets'
                    result=pexpect_session.before
                    print result
                    if self.parse_ping_output(result,self.pkt_cnt) !=0:
                        results[dest_ep]['udp']=1
                    else:
                        results[dest_ep]['udp']=0
        return results
