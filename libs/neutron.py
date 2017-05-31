#!/usr/bin/env python
import sys
import re
from time import sleep
from fabric.api import cd, run, env, hide, get, settings
from fabric.context_managers import *
from neutronclient.v2_0 import client as nclient
from testcases.config import conf

class neutronPy(object):
    def __init__(self, controllerIp, username='admin', password='noir0123', tenant='admin'):
        cred = {}
        cred['username'] = username
        cred['password'] = password
        cred['tenant_name'] = tenant
        cred['auth_url'] = "http://%s:5000/v2.0/" % controllerIp
        self.client = nclient.Client(**cred)

    def create_router(self,name,shared=False):
	body_value = {'router': {
    			'name' : name,
    			'admin_state_up': True,
			'shared' : shared
		     }}
	try:
	    router = self.client.create_router(body=body_value)
	    return router['router']['id']
	except Exception as e:
	    print "Router Create failed: ", repr(e)
	    raise

    def get_router_list(self):
        """ returns list of routers """
        return self.client.list_routers()['routers']

    def get_router_attribute(self, router_name, attribute):
        ret = None
        rl = self.get_router_list()
        for r in rl:
            if r['name'] == router_name:
                if attribute in r.keys():
                    ret = r[attribute]
                    break
        return ret

    def router_set_rem_gw(self,rtr_name,action,ext_net_name=''):
	#Pass ext_net_name ONLY when action is 'set'
	try:
	    rtr_id = self.get_router_attribute(rtr_name,'id')
	    if action == 'set':
	    	ext_net_id = self.get_network_attribute(ext_net_name,'id')
	    	rtr_id = self.get_router_attribute(rtr_name,'id')
	    	print ext_net_id, rtr_id
	    	rtr_dict = {'network_id':ext_net_id}
	    	self.client.add_gateway_router(rtr_id, rtr_dict)
	    if action == 'rem':
		self.client.remove_gateway_router(rtr_id)
	except Exception as e:
	    print "Set/Removal router-gateway failed: ",repr(e)
	    return 0

    def attach_detach_router_subnet(self,rtr_name,subnetID,action):
	try:
	    rtr_id = self.get_router_attribute(rtr_name,'id')
	    rtr_dict = {'subnet_id':subnetID}
	    if action == 'add':
		self.client.add_interface_router(rtr_id, rtr_dict)
	    if action == 'rem':
		self.client.remove_interface_router(rtr_id, rtr_dict)
	except Exception as e:
	    print "Attach/Detach router from network failed: ",repr(e)
	    raise
		

    def create_net(self, netname, **kwargs):
	try:
            cn = {'network': {'name': netname, 'admin_state_up': True}}
	    for arg,val in kwargs.items():
		cn['network'][arg] = val
            netw = self.client.create_network(body=cn)
            nid = netw['network']['id']
            return nid
	except Exception as e:
	    raise
   
    def create_subnet(self, name, cidr, netid, **kwargs):
	try:
            csn = {'subnets': [{'name': name, 'cidr': cidr, 'ip_version': 4, 'network_id': netid}]}
	    for arg,val in kwargs.items():
		csn['subnets'][0][arg] = val
            snid = self.client.create_subnet(body=csn)
            return snid['subnets'][0]['id']
	except Exception as e:
	    raise

    def create_port(self, network_id, **kwargs):
	try:
	    pt = {'port': {'admin_state_up': True,\
			   'network_id' : network_id}}
	    for arg,val in kwargs.items():
		if arg == 'fixed_ips':
		    val = [{'ip_address': val}]
		pt['port'][arg]=val
	    port = self.client.create_port(body=pt)
	    portid = port['port']['id']
	    return portid
	except Exception as e:
	    raise

    def get_network_list(self):
        return self.client.list_networks()['networks']

    def get_network_attribute(self, network_name, attribute):
        ret = None
        nl = self.get_network_list()
        for n in nl:
            if n['name'] == network_name:
                if attribute in n.keys():
                    ret = n[attribute]
                    break
        return ret

    def get_port_list(self):
        return self.client.list_ports()['ports']

    def get_all_port_details(self, prop=''):
	port_details = {}
	try:
	    for port in self.get_port_list():
		# Fetching standard port properties
                port_details[port['id']] = {'owner' : port['device_owner'],
 				        'network' : port['network_id'],
					'ip' : port['fixed_ips'][0]['ip_address'],
					'status' : port['status'],
					'allowed_address_pairs' : port['allowed_address_pairs']
					}
	        if prop and prop not in port_details[port['id']].keys(): #If not among above port_properties
		    port_details[port['id']][prop] = port[prop]
	except Exception as e:
	    raise
	return port_details
    
    def update_port(self,portID,port_prop={}):
	try:
	    body = {"port" : port_prop}
	    return self.client.update_port(portID,body=body)
	except Exception as e:
		raise
	

    def get_dhcp_port_details(self):
	details = self.get_all_port_details()
	dhcp_ports = {}
	for prop in details.values():
	    if prop['owner'] == 'network:dhcp':
	        dhcp_ports[prop['network']] = prop['ip']
	return dhcp_ports

    def get_port_by_owner(self, owner):
        ret = None
        for p in self.get_port_list():
            if p['device_owner'] == owner:
                return p['id']
        return ret

    def delete_unwanted_router(self):
        """ 
            get the subnet id of private network of router1 
            very specific for gbp openstack installation
        """
        subnet = self.get_network_attribute('private', 'subnets')[0]
        routerid = self.get_router_attribute('router1', 'id')
        privatenetid = self.get_network_attribute('private','id')
        publicnetid = self.get_network_attribute('public','id')

        if subnet and routerid:
            self.client.remove_interface_router(routerid, {'subnet_id': subnet})
        if routerid:
            self.client.delete_router(routerid)
        if privatenetid:
            self.client.delete_network(privatenetid)
        if publicnetid:
            self.client.delete_network(publicnetid)

class neutronCli(object):

    def __init__(self,controllerIp,username='root',password='noir0123'):
	self.controller = controllerIp
	self.username = username
	self.password = password
	
    def runcmd(self,cmd):
        env.host_string = self.controller
        env.user = self.username
        env.password = self.password
        srcRc = 'source /root/keystonerc_admin'
        with prefix(srcRc):
		try:
                   _output = run(cmd)
		   return _output
		except:
		   pass

    def addDelkeystoneTnt(self,tenantList,action):
	'''
	Add/Delete Tenants in Openstack
	action: valid strings are 'create','delete'
	'''
	if not isinstance(tenantList,list):
	    tenantList = [tenantList]
	tenant_id_list = []
	for tnt in tenantList:
	    if action == 'create':
		cmd_tnt = 'openstack project create %s' %(tnt)
		tenant_id = self.getuuid(self.runcmd(cmd_tnt))
		cmd_user = 'openstack role add --user admin --project %s admin' %(tnt)
		self.runcmd(cmd_user)
		if tenant_id:
		    tenant_id_list.append(tenant_id)
	    if action == 'delete':
		for tnt in tenantList:
		    cmd = 'openstack project delete %s' %(tnt)
		    self.runcmd(cmd)
	if action == 'create':
	    if len(tenant_id_list) == 1:
		return tenant_id_list[0]
	    if len(tenant_id_list) > 1:
		return tenant_id_list

    def getuuid(self,cmd_out):
        '''
        Extracts UUID of the neutron object
        '''
	if cmd_out:
            match=re.search("\\bid\\b\s+\| (.*) \|",cmd_out,re.I)
            if match:
               obj_uuid = match.group(1)
               return obj_uuid.rstrip()
	return 0

    def netcrud(self,name,action,\
                tenant='admin',external=False, 
                shared=False, aim=''):
        if action == 'create':
	   if external:
	        if shared:
	           cmd = 'neutron --os-tenant-name %s net-create %s --router:external --shared' %(tenant,name)
	        else:
	           cmd = 'neutron --os-tenant-name %s net-create %s --router:external' %(tenant,name)
                if aim:
                   cmd = cmd + ' %s' %(aim)
	   else:
	        cmd = 'neutron --os-tenant-name %s net-create %s' %(tenant,name)
	   ntkId = self.getuuid(self.runcmd(cmd))
	   if ntkId:
	       #print 'Output of ID ==\n', ntkId
	       return ntkId
	if action == 'delete':
	   cmd = 'neutron --os-tenant-name %s net-delete %s' %(tenant,name)
           self.runcmd(cmd)

    def subnetcrud(self,name,action,ntkNameId,cidr=None,tenant='admin',
                   extsub=False,aim='',subnetpool='' ):
	"""
	Create/Delete subnets for a given tenant
	action: 'create' or 'delete' are the only valid strings to pass
        ntkNameId: name of the netk, mandatory to pass when action == create
        cidr: Mandatory to pass when action == create
        """
	if action == 'create':
            if extsub:
	        cmd = 'neutron --os-tenant-name %s subnet-create %s %s --name %s --disable-dhcp'\
                      %(tenant,ntkNameId,cidr,name)
                if aim:
                    cmd = cmd +' %s' %(aim)
            else:
		if subnetpool:
		    cmd = 'neutron --os-tenant-name %s ' %(tenant)+\
			  'subnet-create %s --subnetpool %s --name %s'\
			  %(ntkNameId,subnetpool,name)
		else:
	            cmd = 'neutron --os-tenant-name %s subnet-create %s %s --name %s'\
			  %(tenant,ntkNameId,cidr,name) 
	    subnetId = self.getuuid(self.runcmd(cmd))
	    if subnetId:
	       return subnetId
	if action == 'delete':
	   cmd = 'neutron --os-tenant-name %s subnet-delete %s' %(tenant,name)	  
	   self.runcmd(cmd)

    def rtrcrud(self,name,action,rtrprop='',gw='',subnet='',tenant='admin'):
        """
        name: router name or UUID
 	action: Valid strings are 'create','delete','add','set','clear'
	rtrprop: Valid strings are 'gateway' or 'interface'
	gw: Name or ID of the External Netk. Mandatory param when rtrprop='gateway'
        subnet: Name or ID of the subnet. Mandatory when rtrprop='interface'
        """
 	if rtrprop == 'gateway':
	   cmd = 'neutron --os-tenant-name %s router-gateway-%s %s %s' %(tenant,action,name,gw)
	if rtrprop == 'interface':
	   cmd = 'neutron --os-tenant-name %s router-interface-%s %s subnet=%s' %(tenant,action,name,subnet)
	if not rtrprop:
	   cmd = 'neutron --os-tenant-name %s router-%s %s' %(tenant,action,name)
	   if action == 'create':
	      rtrId = self.getuuid(self.runcmd(cmd))
	      if rtrId:
	          return rtrId
	self.runcmd(cmd) 	   		
	
    def addscopecrud(self, name, action, tenant='admin', ip=4,
		     shared=False, apicvrf=''):
        if action == 'create':
	    if shared:
	           cmd = 'neutron --os-tenant-name %s ' %(tenant)+\
			 'address-scope-create --shared %s %s ' %(name,ip)
	    else:
	           cmd = 'neutron --os-tenant-name %s ' %(tenant)+\
			 'address-scope-create %s %s ' %(name,ip)
	    if apicvrf:
	    	cmd = cmd + ' %s' %(apicvrf)
	    ascId = self.getuuid(self.runcmd(cmd))
	    if ascId:
	       #print 'Output of ID ==\n', ascId
	       return ascId
	if action == 'delete':
	   cmd = 'neutron --os-tenant-name %s address-scope-delete %s' %(tenant,name)
           self.runcmd(cmd)

    def subpoolcrud(self,name,action,address_scope='', pool='',
		       prefix_len=28,tenant='admin', shared=False):
	#if action:: 'create' , ONLY then address_scope,pool are mandatory
        if action == 'create':
	    if shared:
	           cmd = 'neutron --os-tenant-name %s subnetpool-create ' %(tenant)+\
			 '--address-scope %s --shared ' %(address_scope)+\
			 '--pool-prefix %s --default-prefixlen %s %s' \
			 %(pool,prefix_len,name)
	    else:
	           cmd = 'neutron --os-tenant-name %s subnetpool-create ' %(tenant)+\
			 '--address-scope %s ' %(address_scope)+\
			 '--pool-prefix %s --default-prefixlen %s %s' \
			 %(pool,prefix_len,name)
	    spId = self.getuuid(self.runcmd(cmd))
	    if spId:
	       #print 'Output of ID ==\n', spId
	       return spId
	if action == 'delete':
	   cmd = 'neutron --os-tenant-name %s subnetpool-delete %s' %(tenant,name)
           self.runcmd(cmd)

    def Stripper(self,cmdout):
	"""
	Not the Las Vegas one
	"""
	_out = cmdout.split('\n')
	final_out = _out[3:len(_out) - 1]
	final_IDlist = [x.strip(' ') for x in [item.strip('|\r') for item in final_out]]
	return final_IDlist

    def deleteAll(self,tenant):
	cmd = 'neutron --os-tenant-name %s router-list -c id' %(tenant)
	cmd_out = self.runcmd(cmd)
	if cmd_out:
	    rtrList = self.Stripper(cmd_out)
	    for rtr in rtrList:
	         rtrout = self.runcmd('neutron --os-tenant-name %s router-port-list %s -c id' %(tenant,rtr))
		 if rtrout:
		    rtrportList = self.Stripper(rtrout)
		    print rtrportList
		    for port in rtrportList:
		        portdelcmd = 'neutron --os-tenant-name %s router-interface-delete %s port="%s"' %(tenant,rtr,port)
			self.runcmd(portdelcmd)
		 self.runcmd('neutron --os-tenant-name %s router-delete %s' %(tenant,rtr))   
	cmdnet = 'neutron --os-tenant-name %s net-list -c id' %(tenant)
	cmdOut = self.runcmd(cmdnet)
	if cmdOut:
		netList = self.Stripper(cmdOut)
	if netList:
	   for net in netList:
		self.runcmd('neutron --os-tenant-name %s net-delete %s' %(tenant,net))

    def alternate_az(self,avzone):
	"Alternately returns AvailZone for alternate VM placement"
	while True:
	    yield avzone
            yield 'nova'

    def spawnVM(self,tenant,vmname,net='',port='',availzone=''):
        """
        Method for spawning VMs using net-id or port-id
	availzone:: pass it as <zone-name>|<hostname>
	hostname as it appears in nova hypervisor-list
        """
        image = conf['vm_image']
        flavor = conf['vm_flavor']
        if net:
           cmd = 'nova --os-tenant-name %s boot %s --image %s --flavor %s --nic net-id=%s' %(tenant,vmname,image,flavor,net)
        if port:
           cmd = 'nova --os-tenant-name %s boot %s --image %s --flavor %s --nic port-id=%s' %(tenant,vmname,image,flavor,port)
	if availzone:
	   cmd = cmd+' --availability-zone %s' %(availzone)
        if self.runcmd(cmd):
	    sleep(5)
	    vmout = self.runcmd('nova --os-tenant-name %s show %s | grep network' %(tenant,vmname))
	    match = re.search("\\b(\d+.\d+.\d+.\d+)\\b.*",vmout,re.I)
	    if match:
		vmip = match.group(1)
		num_try = 1
		while num_try < 6:
		    sleep(5)
		    _out = self.runcmd('nova --os-tenant-name %s interface-list %s | grep ACTIVE'\
				   %(tenant,vmname))
		    if _out or num_try == 5:
		         break
		    num_try+=1
		if _out: #It may happen even after above 5 retries,_out is still NoneType, so check for that
		    if _out.succeeded:
		        portMAC = re.search(r'(([0-9a-f]{2}:){5}[0-9a-f]{2})',_out,re.I).group()
		        _match = [i.strip(' ') for i in _out.split('|')]
		        portID = _match[_match.index('ACTIVE')+1]
	            return [vmip,portID,portMAC]
		else:
		     return []
	else:
	    return []

    def purgeresource(self,tenantIDList,resourceOnly=False):
        "Method to clean resources"
        if not isinstance(tenantIDList,list):
            tenantIDList = [tenantIDList]
	for tenant_id in tenantIDList:
	    cmd1 = 'gbp purge %s' %(tenant_id)
	    cmd2 = 'aimctl manager application-profile-delete prj_%s OpenStack' %(tenant_id)
	    cmd3 = 'aimctl manager tenant-delete  prj_%s' %(tenant_id)
	    cmd4 = 'openstack project delete %s' %(tenant_id)
	    for cmd in [cmd1, cmd2, cmd3, cmd4]:
	        self.runcmd(cmd) #Only cmd1, i.e. gbp/neutron resource will be deleted
		if resourceOnly:
		    break
    
