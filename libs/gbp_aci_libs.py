#!/usr/bin/env python
# Copyright (c) 2016 Cisco Systems
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import json
import requests
import sys
from fabric.api import cd,run,env, hide, get, settings, local, lcd
from raise_exceptions import *
from passwdlib import *

class gbpApic(object):
    def __init__(self, addr,mode='gbp',apicsystemID='noirolab',\
                 username='admin', password='noir0123', ssl=True):
        self.addr = addr
        self.ssl = ssl
        self.user = username
        self.passwd = password
	self.apicsystemID = apicsystemID
	if mode == 'aim':
	    self.appProfile = 'ap-OpenStack' #By default comes in aim.conf in controller
	elif mode == 'ml2':
            self.appProfile = 'ap-%s' %(self.apicsystemID)
	else:
            self.appProfile = 'ap-%s_app' %(self.apicsystemID)
        self.cookies = None
        self.login()
      
    def exec_admin_cmd(self,ip,cmd='',passwd='noir0123'):
        env.host_string = ip
        env.user = "admin"
        env.password = passwd
        env.disable_known_hosts = True
        r = run(cmd)
        if r.failed:
            raise ErrorRemoteCommand("---ERROR---: Error running %s on %s as user admin, stderr %s" % (cmd, ip, r.stderr))
        return r

    def get_root_password(self,ip,passwd='noir0123'):
        token = self.exec_admin_cmd(ip,cmd="acidiag dbgtoken",passwd=passwd)
        with lcd('/root/gbpauto/libs'):
           password = local("./getrootpwd.py %s" % token, capture=True)
        print 'Root Password == ',password
        return password

    def exec_root_cmd(self,ip,cmd):
        env.host_string = ip
        env.password = self.get_root_password(ip)
        print env.password
        env.user = "root"
        env.disable_known_hosts = True
        out = run(cmd)
        if out.failed:
            raise ErrorRemoteCommand(
                  "---ERROR---: Error running %s on %s as user root,"
                  "stderr %s" % (cmd,ip,out.stderr))
        return out

    def apic_verify_mos(self,apic_ip,objs,tenant='admin',uname='admin',passwd='noir0123'):
        """
        Function to verify MOs in APIC
        """
        #TODO:Once actual implmentation is done , below code will be discarded
        if not isinstance(objs,list):
           objs = [objs]
        env.host_string = apic_ip
        env.user = uname
        env.password = passwd
        _output = run("ls -ltr /mit/uni/tn-%s" %(tenant))
        for obj in objs:
            regex = re.compile(r"\W%s\W" %(obj))
            if not bool(regex.search(_output)):
                 return 0
        return 1

    def dev_conn_disconn(self,rem_ip,action):
        """
        Function to connect/disconnect any device from the local device
        Primarily we are using for disconnecting APIC from Ostack Controller
        rem_ip = the ip of the remote device
        action = 'disconnect' or 'reconnect' are the valid strings
        """
        if action == 'disconnect':
           cmd = "ip route add %s/32 via 127.0.0.1" %(rem_ip)
        elif action == 'reconnect':
           cmd = "ip route del %s/32" %(rem_ip)
        else:
            print "Passing Invalid string for param 'action'"
            return 0
        if local(cmd).succeeded:
               return 1
        else:
               return 0

    def enable_disable_switch_port(self,apic_ip,switch_node_id,action,port):
        """
        Using APIC user can Admin DOWN/UP a Leaf/Spine Port
        switch_node_id :: NodeID of Leaf/Spine
        action:: 'enable' or 'disable'
        port:: Port of the Leaf/Spine
        """
        env.host_string = apic_ip
        env.user = 'admin'
        env.password = self.passwd
        if action == 'enable':
           cmd = 'switchport %s switch %s interface %s' %(action,switch_node_id,port)
        if action == 'disable':
           cmd = 'switchport %s switch %s interface %s' %(action,switch_node_id,port)
        _output = run(cmd)
        print _output
        return 1

    def reboot_aci(self,ip,node='leaf'):
        """
        Reboot APIC/Leaf/Spine
        ip:: ip of the aci device to be rebooted
        """
        
        if node == 'apic':
           cmd = 'reload controller 1'
        else:
           cmd = 'system-reboot'
        self.exec_admin_cmd(ip,cmd, passwd=self.passwd)
        return 1

    def aciStatus(self,apic_ip,node,nodetype='leaf',status='active'):
        """
        Verify the node status in ACI
        node: leaf or spine's hostname
        """
        cmdout = self.exec_admin_cmd(apic_ip,'acidiag fnvread | grep %s' %(node), passwd=self.passwd)
        if re.search('\d+\s+%s\s+[A-Z0-9]+\s+\d+.\d+.\d+.\d+\/32\s+\\b%s\s+\d\s+\\b%s' %(node,nodetype,status),cmdout,re.I) != None:
           return 1
           
    def url(self, path):
        if self.ssl:
            return 'https://%s%s' % (self.addr, path)

    def login(self):
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' % (self.user, self.passwd)
        path = '/api/aaaLogin.json'
        req = requests.post(self.url(path), data=data, verify=False)
        if req.status_code == 200:
            resp = json.loads(req.text)
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.cookies = {'APIC-Cookie': token}
        return req

    def post(self, path, data):
	try:
            return requests.post(self.url(path),
					  data=data,
					  cookies=self.cookies,
					  verify=False)
	except requests.exceptions.RequestException as e:
	    print e
	    return None

    def get(self,path):
	try:
            return requests.get(self.url(path),
			        cookies=self.cookies,
				verify=False)
	except requests.exceptions.RequestException as e:
		print e
		return None

    def delete(self,path):
	try:
            return requests.delete(self.url(path),
				   cookies=self.cookies,
				   verify=False)
	except requests.exceptions.RequestException as e:
		print e
		return None

    def getTenant(self,getName=''):
        """
        Method to get the tenantDN from APIC
        which will correspond to an openstack project/tenant
        get_name :: Pass the displayname(i.e. the Openstack Project
		    Name) and in return get the tntname(prj_*).
		    This flag is useful ONLY for MergedPlugin
        """
        tenants = {}
        pathtenants = '/api/node/mo/uni.json?'+\
                      'query-target=subtree&target-subtree-class=fvTenant'
        reqfortnts = self.get(pathtenants)
        details = reqfortnts.json()['imdata']
        #NOTE: In aim-aid, UUID will be used instead of name
        #and the exact ostack proj-name will appear as name-alias
        #In aim-aid, nameAlias is always True, then 'name' attribute
        #will be the UUID of the Ostack Project
        for item in details:
            try:
                #tntname will be UUID for Ostack projects
                tntname = item['fvTenant']['attributes']['name']
                if tntname not in ['common','mgmt','infra']:
		    if getName and\
		      getName == item['fvTenant']['attributes']['nameAlias']:
			return tntname
                    tntdn = item['fvTenant']['attributes']['dn']
                    if item['fvTenant']['attributes']['nameAlias']:
                        tntdispname = item['fvTenant']['attributes']['nameAlias']
                        tenants[tntdispname]=tntdn
                    else:
		       tenants[tntname]=tntdn
                       raise Exception(
                       "nameAlias is NOT FOUND in APIC for Tenant %s" %(tntname))
            except Exception as e:
                print 'WARNING: '+repr(e)       
                pass
        return tenants

    def getEpgOper(self,tnt):
	"""
        Method to fetch EPG and their Endpoints iand BD for a given tenant
        tntdn: tenant's DN, incase of 'common' tenant, pass tntdn as 'common'
	"""
	finaldictEpg = {}
        if tnt == 'common':
               tntdn = 'uni/tn-common'
	else:
	    tntdn = self.getTenant()[tnt]
	tenantepgdict = {}
	pathtenantepg = '/api/node/mo/%s/%s.json?query-target=children&target-subtree-class=fvAEPg'\
                            %(tntdn,self.appProfile)
	reqforepgs = self.get(pathtenantepg)
        tntDetails = reqforepgs.json()['imdata']
  	for item in tntDetails:
            try:
                epgName = item['fvAEPg']['attributes']['name']
		epgDn = item['fvAEPg']['attributes']['dn']
                tenantepgdict[epgDn] = epgName
            except Exception as e:
                print 'WARNING: '+repr(e)
                return {}
	if len(tenantepgdict):
	        for dn,epgname in tenantepgdict.iteritems():
		    finaldictEpg[epgname] = {}
	            pathepfromepg = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvCEp' %(dn)
	            reqforeps = self.get(pathepfromepg)
                    epgDetails = reqforeps.json()['imdata']
                    for item in epgDetails:
			vmname = item['fvCEp']['attributes']['contName'].encode()
		        finaldictEpg[epgname][vmname]={}
			finaldictEpg[epgname][vmname]['status'] = item['fvCEp']['attributes']['lcC'].encode()
			finaldictEpg[epgname][vmname]['ip'] = item['fvCEp']['attributes']['ip'].encode()
			finaldictEpg[epgname][vmname]['encap'] = item['fvCEp']['attributes']['encap'].encode()
			finaldictEpg[epgname][vmname]['mcastaddr'] = item['fvCEp']['attributes']['mcastAddr'].encode()
		    pathbdfromepg = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvRsBd' %(dn)
		    reqforbd = self.get(pathbdfromepg)
		    detail = reqforbd.json()['imdata']
		    finaldictEpg[epgname]['bdname'] = detail[0]['fvRsBd']['attributes']['tnFvBDName'].encode()
		    finaldictEpg[epgname]['bdstate'] = detail[0]['fvRsBd']['attributes']['state'].encode()
        print 'EPG Details == \n', finaldictEpg
	return finaldictEpg
           
    def getBdOper(self,tnt):
	"""
	Method to fetch subnets,their scopes,L3out association
	"""
        finaldictBD = {}
        if tnt == 'common':
               tntdn = 'tn-common'
	else:
	    tntdn = self.getTenant()[tnt]
	tenantbddict = {}
	pathtenantbd = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvBD'\
			   %(tntdn)
	#print 'Tenant BD Path', pathtenantbd
	reqforbds = self.get(pathtenantbd)
	tntDetails = reqforbds.json()['imdata']
	for item in tntDetails:
		bdName = item['fvBD']['attributes']['name'].encode()
		bdDn = item['fvBD']['attributes']['dn'].encode()
		tenantbddict[bdDn] = bdName
	if len(tenantbddict):
	        for dn,name in tenantbddict.iteritems():
		    finaldictBD[name] = {}
		    #Fetch Subnets and their Scopes for a given BD
		    pathforbdsubnets = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvSubnet'\
				       %(dn)
		    reqforsubnets = self.get(pathforbdsubnets)
		    subnetDetails = reqforsubnets.json()['imdata']
		    subnetdict = {}
		    for item in range(len(subnetDetails)):
			subnetdict.setdefault('subnet-%s' %(item),{})['ip'] = subnetDetails[item]['fvSubnet']['attributes']['ip'].encode()
			subnetdict['subnet-%s' %(item)]['scope'] = subnetDetails[item]['fvSubnet']['attributes']['scope'].encode()
		    finaldictBD[name]['subnets']=subnetdict
		    # Fetch the VRF associated with a given BD
		    #print 'DN for VRF == \n', dn
		    pathforvrf = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvRsCtx' %(dn)
		    reqforvrf = self.get(pathforvrf)
		    vrfDetails = reqforvrf.json()['imdata']
		    if len(vrfDetails):
			finaldictBD[name]['vrfname'] = vrfDetails[0]['fvRsCtx']['attributes']['tnFvCtxName'].encode()
			finaldictBD[name]['vrfstate'] = vrfDetails[0]['fvRsCtx']['attributes']['state'].encode()
			finaldictBD[name]['vrfdn'] = vrfDetails[0]['fvRsCtx']['attributes']['tDn'].encode()
		    #Fetch L3Out Association for a given BD
		    pathL3OutLink = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvRsBDToOut' %(dn)
		    reqforL3Out = self.get(pathL3OutLink)
		    L3outDetails = reqforL3Out.json()['imdata']
		    if len(L3outDetails):
		       finaldictBD[name]['l3outasso'] = L3outDetails[0]['fvRsBDToOut']['attributes']['tnL3extOutName'].encode()
		    else:
		       finaldictBD[name]['l3outasso'] = ''
		    #Fetch Operational L3Out for a given BD
		    pathL3OutOper = '/api/node/mo/%s.json?rsp-subtree-include=relations&rsp-subtree-class=l3extOut' %(dn)
		    reqforOperL3Out = self.get(pathL3OutOper)
		    OperL3OutDetails = reqforOperL3Out.json()['imdata']
		    try:
		        finaldictBD[name]['l3outoper'] = OperL3OutDetails[0]['l3extOut']['attributes']['name'].encode()
		    except:
			finaldictBD[name]['l3outoper'] = ''
	#print 'BD Details == \n', finaldictBD
	return finaldictBD

    
    def getL3Out(self,tnt):
	"""
	Method to fetch the L3Out, its associated VRF and External Ntk
	for a given Tenant/s
	"""
	finaldictL3Out = {}
	tenantdictL3Out = {}
        if tnt == 'common':
               tntdn = 'tn-common'
	else:
	    tntdn = self.getTenant()[tnt]
	pathtenantL3Outs = '/api/node/mo/%s.json?query-target=children&target-subtree-class=l3extOut' %(tntdn)
	#print 'Tenant L3Out Path', pathtenantL3Outs
	reqforL3Outs = self.get(pathtenantL3Outs)
        tntDetails = reqforL3Outs.json()['imdata']
	for item in tntDetails:
	        l3OutName = item['l3extOut']['attributes']['name'].encode()
		l3OutDn = item['l3extOut']['attributes']['dn'].encode()
		tenantdictL3Out[l3OutDn] = l3OutName
	if len(tenantdictL3Out):
		for dn,name in tenantdictL3Out.iteritems():
		    finaldictL3Out[name] = {}
		    #Fetch the VRF associated with the given L3Out
		    #print 'DN for VRF == \n', dn
		    pathforL3Outvrf = '/api/node/mo/%s.json?query-target=children&target-subtree-class=l3extRsEctx' %(dn)
		    reqforL3Outvrf = self.get(pathforL3Outvrf)
		    vrfDetails = reqforL3Outvrf.json()['imdata']
		    if len(vrfDetails):
			finaldictL3Out[name]['vrfname'] = vrfDetails[0]['l3extRsEctx']['attributes']['tnFvCtxName'].encode()
                        finaldictL3Out[name]['vrfstate'] = vrfDetails[0]['l3extRsEctx']['attributes']['state'].encode()
	#print 'L3 Out Details == \n', finaldictL3Out
	return finaldictL3Out

    def getVrfs(self,tnt):
	"""
	Fetch VRF for tenant/s
	"""
	finalvrfprops = []
        if tnt == 'common':
               tntdn = 'tn-common'
	else:
	    tntdn = self.getTenant()[tnt]
        pathtenantvrf = '/api/node/mo/%s.json?query-target=children&target-subtree-class=fvCtx' %(tntdn)
	reqforvrfs = self.get(pathtenantvrf)
	tntDetails = reqforvrfs.json()['imdata']
	for item in tntDetails:
		finalvrfprops.append(item['fvCtx']['attributes']['name'].encode())
	return finalvrfprops

    def getHyperVisor(self):
        """
        Return Connection Status of the Hypervisors
        """
        path = '/api/node/class/opflexODev.json'
        req = self.get(path)
        details = req.json()['imdata']
        hypervisor = {}
        if len(details):
           for comp in details:
               name = comp['opflexODev']['attributes']['hostName'].encode()
               hypervisor.setdefault(name,{})['status'] = comp['opflexODev']['attributes']['state'].encode()
               hypervisor[name]['domname'] = comp['opflexODev']['attributes']['domName'].encode()
               hypervisor[name]['cntrlname'] = comp['opflexODev']['attributes']['ctrlrName'].encode()
           print hypervisor
        return hypervisor

    def deletetenants(self):
        """
        Deletes all user created tenants on the APIC
        """
        path = '/api/node/mo/uni.json?query-target=subtree&target-subtree-class=fvTenant'
        req = self.get(path)
        tenantlist = []
        for fvtenant in req.json()['imdata']:
            tenantlist.append(fvtenant['fvTenant']['attributes']['dn'])
        for donotdel in ['uni/tn-common','uni/tn-infra','uni/tn-mgmt']:
            tenantlist.remove(donotdel)
        print 'List of Tenants to be deleted ==\n', tenantlist
        for deltnt in tenantlist:
            path = '/api/node/mo/%s.json' %(deltnt)
            self.delete(path)

    def create_add_filter(self,tnt):
        """
        svcepg: Preferably pass a list of svcepgs if more than one
        """
        #Create the noiro-ssh filter with ssh & rev-ssh subjects
        if tnt == 'common':
               tntdn = 'tn-common'
        else:
            tntdn = self.getTenant()[tnt]
        path = '/api/node/mo/%s/flt-noiro-ssh.json' %(tntdn)
        data = '{"vzFilter":{"attributes":{"dn":"%s/flt-noiro-ssh","name":"noiro-ssh","rn":"flt-noiro-ssh","status":"created,modified"},"children":[{"vzEntry":{"attributes":{"dn":"%s/flt-noiro-ssh/e-ssh","name":"ssh","etherT":"ip","prot":"tcp","sFromPort":"22","sToPort":"22","rn":"e-ssh","status":"created,modified"},"children":[]}},{"vzEntry":{"attributes":{"dn":"%s/flt-noiro-ssh/e-rev-ssh","name":"rev-ssh","etherT":"ip","prot":"tcp","dFromPort":"22","dToPort":"22","rn":"e-rev-ssh","status":"created,modified"},"children":[]}}]}}' %(3*(tntdn,))
        results = self.post(path, data)
        print results
        # Fetch all the Svc* contracts for this tenant
        pathtntcont = '/api/node/mo/%s.json?query-target=children&target-subtree-class=vzBrCP' %(tntdn)
        reqforconts = self.get(pathtntcont)
        tntDetails = reqforconts.json()['imdata']
        tntcontdn = {}
        for item in tntDetails:
            if 'Svc' in item['vzBrCP']['attributes']['name'].encode():
                tntcontdn[item['vzBrCP']['attributes']['name'].encode()] = item['vzBrCP']['attributes']['dn']
        # Add the noiro-ssh filter to every Svc-contract in this tenant
        for ctname,ctdn in tntcontdn.iteritems():
            #print ctname, ctdn
            path = '/api/node/mo/%s/subj-%s.json' %(ctdn,ctname)
            #print path
            data = '{"vzRsSubjFiltAtt":{"attributes":{"tnVzFilterName":"noiro-ssh","status":"created,modified"},"children":[]}}'
	    self.post(path, data)
        return 1
    
    def addRouteInShadowL3Out(self,l3p,l3out,extPol,subnet,tntdn='admin'):
        
        shdL3out = '%s_Shd-%s-%s' %(self.apicsystemID,l3p,l3out)
        shdExtPol = '%s_Shd-%s-%s' %(self.apicsystemID,l3p,extPol)
        path = '/api/node/mo/%s/'%(tntdn)+\
               'out-_%s/' %(shdL3out)+'instP-_%s/extsubnet-[%s].json'\
               %(shdExtPol,subnet)
        dn = path.lstrip('/api/node/mo').rstrip('.json')
        print 'DN for Adding Route in ShdL3Out == ',dn
        data = '{"l3extSubnet":{"attributes":{"dn":"%s","ip":"%s",' %(dn,subnet)+\
               '"aggregate":"","rn":"extsubnet-[%s]",' %(subnet)+\
               '"status":"created"},"children":[]}}'
        print 'DATA for Adding Route in ShdL3Out == \n', data
        req = self.post(path,data)
        print req

    def addEnforcedToPtg(self,epg,tnt,flag='enforced'):
        """
        Add Enforced flag to the PTG
        """
        if tnt == 'common':
               tntdn = 'tn-common'
        else:
            tntdn = self.getTenant()[tnt]
        path = '/api/node/mo/%s/%s/epg-%s.json' %(tntdn,self.appProfile,epg)
        data = '{"fvAEPg":{"attributes":{"dn":"%s/%s/epg-%s","pcEnfPref":"%s"},"children":[]}}' %(tntdn,self.appProfile,epg,flag)
        req = self.post(path, data)
        print req

    def enable_disable_switch_port(self,port,leaf_id,action):
        """
        Enable/disable port on the Leaf
        action = 'enable' or 'disable'
        """
        path = '/api/node/mo/uni/fabric/outofsvc.json'
        if action == 'disable':
           data = '{"fabricRsOosPath":{"attributes":{"tDn":"topology/pod-1/paths-%s/pathep-[%s]","lc":"blacklist"},"children":[]}}' %(leaf_id,port)
        if action == 'enable':
           data = '{"fabricRsOosPath":{"attributes":{"dn":"uni/fabric/outofsvc/rsoosPath-[topology/pod-1/paths-%s/pathep-[%s]]","status":"deleted"},"children":[]}}' %(leaf_id,port)
        print data
        req = self.post(path,data)
        print req

