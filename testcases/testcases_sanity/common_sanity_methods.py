#!/usr/bin/python

import logging
import re
import string
import sys
from commands import *
getoutput("rm -rf /tmp/test_*") #Deletes pre-existing test logs
from time import sleep
from libs.gbp_aci_libs import *
from libs.gbp_utils import *
from libs.neutron import *
from libs.gbp_compute import *
from libs.gbp_crud_libs import GBPCrud
from libs.gbp_pexp_traff_libs import gbpExpTraff
from libs.gbp_pexp_traff_libs import gbpExpTraffNoHping3
from testcases.config import conf
from testcases.testcases_nat_func.traff_from_extgw import *

# Initialize logging
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
# create a logfile handler
hdlr = logging.FileHandler('/tmp/test_sanity.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
hdlr.setFormatter(formatter)
# Add the handler to the logger
LOG.addHandler(hdlr)

#Extract and set global vars from config file
#NOTE:The external-segment is hardcoded to 'Management-Out'
CNTRLIP = conf['controller_ip']
APICIP = conf['apic_ip']
TNT_LIST_ML2 =  ['PENGUIN','OCTON','GARTH']
TNT_LIST_GBP = ['MANDRAKE', 'BATMAN']
ML2vms = {'PENGUIN' : ['PVM1','PVM2'],
	  'OCTON' : ['OVM3', 'OVM4'],
	  'GARTH' : ['GVM5', 'GVM6']}
GBPvms = {'MANDRAKE' : ['MVM1','MVM2','MVM3','MVM4'],
          'BATMAN' : ['BVM3','BVM4']}
EXTRTR = conf['ext_rtr']
EXTRTRIP1 = conf['extrtr_ip1']
EXTRTRIP2 = conf['extrtr_ip2']
AVZONE = conf['nova_az_name']
AVHOST = conf['az_comp_node']
COMPUTE1 = conf['network_node']
COMPUTE2 = conf['compute-2']
pausetodebug = conf['pausetodebug']
EXTDNATCIDR,FIPBYTES = '50.50.50.0/28', '50.50.50.'
EXTSNATCIDR = '55.55.55.0/28'
EXTNONATCIDR = '2.3.4.0/24' #Can be any cidr, jsut needed for neutron router
#We want to re-purpose the CIDR of PvtNtk for VMs participating in NO-NAT
NONATCIDR = '60.60.60.0/24'
APICVRF = "--apic:distinguished_names type=dict"+\
	  " VRF='uni/tn-common/ctx-DcExtVRF'"
ML2Fips = {}
GBPFips = {}
ACT = 'ALLOW'
CLS_ICMP = 'ICMP'
CLS_TCP = 'TCP'
PR_ICMP = 'PR-ICMP'
PR_TCP = 'PR-TCP'
PRS_ICMP_TCP = 'CONT-ICMP-TCP'
PRS_ICMP = 'CONT-ICMP'
PRS_TCP = 'CONT-TCP'
ml2_vm_ntk_ip = {}
gbp_vm_ntk_ip = {}
comp1 = Compute(COMPUTE1)
comp2 = Compute(COMPUTE2)
neutron = neutronCli(CNTRLIP)
neutron_api = neutronPy(CNTRLIP)

def create_external_network_subnets(nat):
	#Needed for both GBP & ML2
        LOG.info(
        "\n#######################################################\n"
        "####  Create Shared External Network for ML2 Tenants   ####\n"
        "#########################################################\n"
        )
	#For nonat, use pre-existing Datacenter-Out
	#Also just add one subnet to that nonat External-Network
	if nat == 'nonat':
            aimntkcfg = '--apic:distinguished_names type=dict'+\
                 ' ExternalNetwork='+\
                 'uni/tn-common/out-Datacenter-Out/instP-DcExtPol'+\
		 " --apic:nat_type ''"
	else:
            aimntkcfg = '--apic:distinguished_names type=dict'+\
                 ' ExternalNetwork='+\
                 'uni/tn-common/out-Management-Out/instP-MgmtExtPol'
            aimsnat = '--apic:snat_host_pool True'
	try:
	    if nat == 'nonat':
	        neutron.netcrud('Datacenter-Out','create',external=True,
                            shared=True, aim = aimntkcfg)
                EXTSUB3 = neutron.subnetcrud('extsub3','create','Datacenter-Out',
 			       cidr=EXTNONATCIDR,extsub=True)
		return EXTSUB3
	    else:
	        neutron.netcrud('Management-Out','create',external=True,
                            shared=True, aim = aimntkcfg)
                EXTSUB1 = neutron.subnetcrud('extsub1','create','Management-Out',
 			       cidr=EXTDNATCIDR,extsub=True)
                EXTSUB2 = neutron.subnetcrud('extsub2','create','Management-Out',
 			       cidr=EXTSNATCIDR,extsub=True,aim=aimsnat)
	        return EXTSUB1, EXTSUB2
      	except Exception as e:
	    LOG.error("Shared External Network Failed: "+repr(e))
            return 0

def attach_fip_to_vms(tnt,mode):
        LOG.info(
        "\n#############################################\n"
        "#### Create & Attach FIP to VMs for the Tenant %s ####\n"
        "###############################################\n"
	%(tnt))
	if mode == 'ml2':
	   vms = ML2vms[tnt]
	   ML2Fips[tnt]= []
	else:
	   vms = GBPvms[tnt]
	   GBPFips[tnt]=[]
	for vm in vms:
	    cmd1 = 'nova --os-tenant-name %s' %(tnt)+\
                  ' floating-ip-create Management-Out'
	    match = re.search('(%s\d+).*'%(FIPBYTES),
                                        neutron.runcmd(cmd1),
					re.I)
	    if match:
		fip = match.group(1)
	    	if mode == 'ml2':
		    ML2Fips[tnt].append(fip)
		else:
		    GBPFips[tnt].append(fip)
	    cmd2 = 'nova --os-tenant-name %s ' %(tnt)+\
                   'floating-ip-associate %s %s' %(vm,fip)
	    neutron.runcmd(cmd2)

def dump_results(mode):
    import commands
    text = commands.getoutput("grep -r %s-SANITY /tmp/test_sanity.log" %(mode)) 
    LOG.info("####### %s TEST RESULTS #######\n%s" %(mode,text))

class TestError(Exception):
	pass

class crudML2(object):
    global ml2tnt1, ml2tnt2, ml2tnt3, ml2Ntks, ml2Subs, Cidrs, addscopename, \
	   addscopename_shd, subpoolname, subpoolname_shd, subpool, \
	   subpool_shd, traffic_class
    ml2tnt1, ml2tnt2, ml2tnt3 = TNT_LIST_ML2[0],TNT_LIST_ML2[1],TNT_LIST_ML2[2]
    ml2Ntks,ml2Subs,Cidrs = {},{},{}
    ml2Ntks[ml2tnt1] = ['Net1', 'Net2']
    ml2Ntks[ml2tnt2] = ['ntk3', 'ntk4']
    ml2Ntks[ml2tnt3] = ['gntk5', 'gntk6']
    ml2Subs[ml2tnt1] = ['Subnet1', 'Subnet2']
    ml2Subs[ml2tnt2] = ['sub3', 'sub4']
    ml2Subs[ml2tnt3] = ['gsub5', 'gsub6']
    addscopename = 'asc1'
    addscopename_shd = 'ascs'
    subpoolname = 'subpool1'
    subpoolname_shd = 'sps'
    subpool = '22.22.22.0/24'
    subpool_shd = NONATCIDR #Repurposing subpool_shd for NONAT
    Cidrs[ml2tnt1] = ['11.11.11.0/28', '21.21.21.0/28']
    if conf.get('no_hping3') and conf['no_hping3'] == 'True':
        traffic_class = gbpExpTraffNoHping3
    else:
        traffic_class = gbpExpTraff

    def create_ml2_tenants(self):
	neutron.addDelkeystoneTnt(TNT_LIST_ML2, 'create')
	return None
    def create_pvt_network_subnets(self,nonat=False):
        LOG.info(
        "\n#######################################################\n"
        "## Create Private Network & Subnet for both ML2 Tenants ##\n"
        "#########################################################\n"
        )
	if nonat:
	    tntlist = [ml2tnt3]
	else:
	    tntlist = [ml2tnt1,ml2tnt2]
	self.subnetIDs = {}
	self.networkIDs = {}
	self.netIDnames = {}
        for tnt in tntlist:
            try:
                # Every Network has just one Subnet, 1:1
                self.subnetIDs[tnt] = []
                self.networkIDs[tnt] = []
                self.netIDnames[tnt] = {}
                for index in range(len(ml2Ntks[tnt])):
                        network = ml2Ntks[tnt][index]
                        subnet = ml2Subs[tnt][index]
                        netID = neutron.netcrud(network,'create',tnt)
                        self.netIDnames[tnt][network] = netID
                        self.networkIDs[tnt].append(netID)
		        if tnt == ml2tnt1:
                            cidr = Cidrs[tnt][index]
                            self.subnetIDs[tnt].append(
                                        neutron.subnetcrud(subnet,
                                                           'create',
                                                           netID,
                                                           cidr=cidr,
                                                           tenant=tnt))
		        elif tnt == ml2tnt3:
			    self.subnetIDs[tnt].append( 
                                        neutron.subnetcrud(subnet,
                                                           'create',
                                                           netID,
                                                           subnetpool=self.subpoolID,
                                                           tenant=tnt))
		        else:
			    self.subnetIDs[tnt].append( 
                                        neutron.subnetcrud(subnet,
                                                           'create',
                                                           netID,
                                                           subnetpool=self.subpoolID,
                                                           tenant=tnt))
            except Exception as e:
                   LOG.error('Create Network/Subnet Failed: '+repr(e))
	           return 0
        return self.netIDnames, self.networkIDs , self.subnetIDs

    def create_add_scope(self,tnt,shared=False,vrf=False):
        LOG.info(
        "\n#############################################\n"
        "####  Create Address-Scope ONLY for Tenant %s ####\n"
        "###############################################\n"
        %(tnt))
	if vrf: #Shared addresscope with attach VRF
	    self.addscopID = neutron.addscopecrud(addscopename_shd,
						'create',
					         tenant=tnt,
					         shared=shared,
						 apicvrf=APICVRF)
  	else:
	    self.addscopID = neutron.addscopecrud(addscopename,
						'create',
					        tenant=tnt,
					        shared=shared)
	if not self.addscopID:
	    	return 0
	
    def create_subnetpool(self,tnt,shared=False):
        LOG.info(
        "\n#############################################\n"
        "####  Create SubnetPool ONLY for Tenant %s ####\n"
        "###############################################\n"
        %(tnt))
	if shared:
	    spname = subpoolname_shd
	    sub_pool = subpool_shd
	    ads_name=addscopename_shd
	else:
	    spname = subpoolname
	    sub_pool = subpool
	    ads_name=addscopename
	self.subpoolID = neutron.subpoolcrud(spname,'create',
                                             address_scope=ads_name,
					     pool=sub_pool,
					     tenant=tnt,
					     shared=shared)
    	if not self.subpoolID:
		return 0

    def create_routers(self):
        LOG.info(
        "\n#############################################\n"
        "####  Create Router for both ML2 Tenants   ####\n"
        "###############################################\n"
        )
        self.rtrIDs = {}
        for tnt in [ml2tnt1,ml2tnt2,ml2tnt3]:
            try:
                _id = neutron.rtrcrud('RTR1', 'create', tenant=tnt)
                self.rtrIDs[tnt] = _id
            except Exception as e:
       		LOG.error('Create Router Failed: '+repr(e))
                return 0
        LOG.info("\nRouter IDs for the respective Tenants == %s" %
                 (self.rtrIDs))

    def attach_routers_to_networks(self,tnt):
        LOG.info(
        "\n#############################################\n"
        "####  Attach Router to networks of the tenant %s ####\n"
        "###############################################\n"
         %(tnt))
        for subnetId in self.subnetIDs[tnt]:
            try:
                neutron.rtrcrud(self.rtrIDs[tnt],'add',rtrprop='interface',\
                            subnet=subnetId, tenant=tnt)
	    except Exception as e:
		LOG.error('Attach Router to Network Failed: '+repr(e))
		return 0
    
    def attach_router_to_extnw(self,tnt,nonat=False):
        LOG.info(
        "\n#############################################\n"
        "####  Attach %s Router to the External Network ####\n"
        "###############################################\n"
	%(tnt))
	if not nonat:
	    gw = 'Management-Out'
	else:
	    gw = 'Datacenter-Out'
 	try:
	    neutron.rtrcrud(self.rtrIDs[tnt], 'set', rtrprop='gateway',
	   		    gw=gw, tenant=tnt)
	except Exception as e:
	    LOG.error('Setting GW for the Router Failed: ' + repr(e))
	    return 0

    def install_tenant_vms(self,tnt):
        LOG.info(
        "\n#############################################\n"
        "####  Install VM for the Tenant %s  ####\n"
        "###############################################\n"
	%(tnt))
        # Since VMs are created with 'default' secgroup, hence
        # adding rules to the default secgroup
        neutron.runcmd(
            'nova --os-tenant-name %s secgroup-add-rule default icmp -1 -1 0.0.0.0/0'
            % (tnt))
        neutron.runcmd(
            'nova --os-tenant-name %s secgroup-add-rule default tcp 22 22 0.0.0.0/0'
            % (tnt))
        neutron.runcmd(
            'nova --os-tenant-name %s secgroup-add-rule default tcp 80 80 0.0.0.0/0'
            % (tnt))
	ml2_vm_ntk_ip[tnt] = {}
        az = neutron.alternate_az(AVZONE)
        for i in range(len(ML2vms[tnt])):
	    ml2_vm_ntk_ip[tnt][ML2vms[tnt][i]] = {}
            try:
                vmcreate = neutron.spawnVM(tnt,
                                           ML2vms[tnt][i],
                                           self.networkIDs[tnt][i],
                                           availzone=az.next()
                                       	   )
		ml2_vm_ntk_ip[tnt][ML2vms[tnt][i]] = [vmcreate[0],self.networkIDs[tnt][i]]
	    except Exception as e:
                LOG.error('VM Creation for tnt %s Failed: ' %(tnt)+repr(e))
                return 0

    def cleanup_ml2(self):
	for tnt in TNT_LIST_ML2:
	    #Delete VMs for a given ML2 tenant
	    for vm in ML2vms[tnt]:
	        neutron.runcmd(
		'nova --os-tenant-name %s delete %s' %(tnt,vm))
	    #Delete FIPs
	    try:
	        if ML2Fips:
		    for fip in ML2Fips[tnt]:
		        neutron.runcmd(
		        'nova --os-tenant-name %s floating-ip-delete %s'
 			 %(tnt,fip))
	    except Exception:
		print 'FIPs do not exist for ',tnt
		pass
	    #Delete Router-ports, gateway and router
	    try:
		if self.rtrIDs[tnt]:
		    for subnet in ml2Subs[tnt]:
		        neutron.runcmd(
		        'neutron router-interface-delete %s %s'
			%(self.rtrIDs[tnt],subnet))
		    neutron.runcmd('neutron router-gateway-clear %s'
		    		   %(self.rtrIDs[tnt]))
		    neutron.runcmd('neutron router-delete %s' 
			           %(self.rtrIDs[tnt]))
	    except Exception:
		print 'Router does not for tenant ',tnt
		pass
	    #Delete Networks
  	    for ntk in ml2Ntks[tnt]:
		    neutron.runcmd('neutron net-delete %s' %(ntk))
	#Delete subnetpool,address-scope,external-network
 	for obj in [subpoolname,subpoolname_shd]:
	    try:
	        neutron.runcmd('neutron subnetpool-delete %s'
		           %(obj))
	    except Exception:
	        pass
	for obj in [addscopename,addscopename_shd]:
	    try:    
	        neutron.runcmd('neutron address-scope-delete %s'
			   %(obj))
	    except Exception:
	        pass
	neutron.runcmd('neutron net-delete Management-Out')
	neutron.runcmd('neutron net-delete Datacenter-Out')

class crudGBP(object):
    from libs.gbp_nova_libs import gbpNova
    global tnt1, tnt2, vms, gbpL3p, gbpL2p, ippool,\
	   gbp_nonat_ads, gbp_nonat_sps
    tnt1, tnt2 = TNT_LIST_GBP
    #tnt2 is primarily used for the purpose of NO-NAT
    gbpL3p = 'L3P1' #tnt2 is using it, while tnt1 uses implicit L3P
    gbpL2p = {tnt1 : ['L2P1','L2P2'],
	      tnt2 : ['L2P3']}
    ippool = {tnt1 : '70.70.70.0/24',
              tnt2 : NONATCIDR}
    gbp_nonat_ads = "nonat_ads"
    gbp_nonat_sps = "nonat_sps"
    vms = {}
    vms[tnt1] = GBPvms[tnt1]
    vms[tnt2] = GBPvms[tnt2]

    def create_gbp_tenants(self):
        neutron.addDelkeystoneTnt(TNT_LIST_GBP, 'create')
	from libs.gbp_nova_libs import gbpNova
        self.gbptnt1 = GBPCrud(CNTRLIP,tenant=tnt1)
        self.gbptnt2 = GBPCrud(CNTRLIP,tenant=tnt2)
        self.gbpadmin = GBPCrud(CNTRLIP)
        self.novatnt1 = gbpNova(CNTRLIP,tenant=tnt1)
        self.novatnt2 = gbpNova(CNTRLIP,tenant=tnt2)
    
    def create_l2p_l3p(self,tnt):
	if tnt == tnt1:
            LOG.info(
            "\n################################################################\n"
            "## Create Explicit L2Policies, Auto-PTGs & implicit L3Policy for Tenant %s ##\n"
            "##################################################################\n"
	    %(tnt))
            LOG.info(
            "\n## Create L2Policy along with it implicit L3Policy ##\n"
	    )
	    self.l2p1_uuid,self.l2p1_impl3p,self.l2p1_autoptg,self.l2p1_ntkid = \
             self.gbptnt1.create_gbp_l2policy(gbpL2p[tnt1][0],
					      getl3p=True,
					      autoptg=True)
            LOG.info(
            "\n## Create L2Policy explicitly associated to above implicit L3Policy ##\n"
	    )
	    self.l2p2_uuid,self.l2p2_autoptg,self.l2p2_ntkid = \
             self.gbptnt1.create_gbp_l2policy(gbpL2p[tnt][1],
                                              autoptg=True,
   				              l3_policy_id=self.l2p1_impl3p)
	    if not self.l2p2_uuid or not self.l2p2_autoptg\
	       or not self.l2p1_uuid or not self.l2p1_impl3p\
	       or not self.l2p1_autoptg:
	         return 0
	    else:
	        LOG.info(
	        "\n## Following resources have been created for Tenant %s:\n"
	        "Implicitly-created L3Policy = %s\n"
	        "Explicit L2Policy_1 = %s and its AutoPTG = %s\n"
	        "Explicit L2Policy_2 = %s and its AutoPTG = %s\n"
	        %(tnt, self.l2p1_impl3p, self.l2p1_uuid, self.l2p1_autoptg,
	        self.l2p2_uuid, self.l2p2_autoptg))
  	if tnt == tnt2:
            LOG.info(
            "\n################################################################\n"
            "## Create Address Scope, Explicit L3Policy, L2Policy for Tenant %s ##\n"
            "##################################################################\n"
	    %(tnt))
	    self.addscopID = neutron.addscopecrud(gbp_nonat_ads,
						'create',
					         shared=True,
						 apicvrf=APICVRF)
	    if self.addscopID:
	        self.subpoolID = neutron.subpoolcrud(gbp_nonat_sps,'create',
                                             address_scope=gbp_nonat_ads,
					     pool=NONATCIDR,
					     shared=True)
    	        if not self.subpoolID:
		    LOG.info("Create of Subnetpool Failed for GBP")
		    return 0
	    else:
		LOG.info("Create of AddressScope Failed for GBP")
		return 0
	    self.l3p_uuid = self.gbptnt2.create_gbp_l3policy(gbpL3p,
					     subnetpools_v4=[self.subpoolID]
						)
	    self.l2p3_uuid,self.l2p3_autoptg,self.l2p3_ntkid = \
             self.gbptnt2.create_gbp_l2policy(gbpL2p[tnt][0],
					      l3_policy_id=self.l3p_uuid,
					      autoptg=True)
	    if not self.l2p3_uuid or not self.l2p3_autoptg:
	         return 0
	    else:
	        LOG.info(
	        "\n## Following resources have been created for Tenant %s:\n"
	        "Explicitly-created L3Policy using AddressScope = %s\n"
	        "Explicit L2Policy = %s and its AutoPTG = %s\n"
	        %(tnt, self.l3p_uuid, self.l2p3_uuid, self.l2p3_autoptg))

    def create_ptg(self):
        LOG.info(
        "\n################################################\n"
        "## Create Explicit PTG using L2P1 for Tenant %s ##\n"
        "##################################################\n"
	%(tnt1))
	self.reg_ptg = self.gbptnt1.create_gbp_policy_target_group(
				'REGPTG',
				l2_policy_id=self.l2p1_uuid
				)
	if not self.reg_ptg:
		 return 0

    def create_policy_target(self,tnt):
	gbp_vm_ntk_ip[tnt]={}
	if tnt == tnt1:
            LOG.info(
            "\n################################################\n"
            "## Create Policy-Targets for two Auto-PTGs and one\n"
            "## Regular PTG for Tenant %s ##\n"
            "##################################################\n"
	    %(tnt))

	#NOTE: 2 PTs/VMs will be created out of self.l2p1_autoptg,
	#so repeating the element in the list, such that this list
	#and the ptlist are of same length
	#VM in sef.regPtg = VM1
	#VMs in self.l2p1_autoptg = VM2 & VM3
	#VM in self.l2p2_autoptg = VM4 
	#NOTE: Since netns needs to be a the property of a VM, needed
	#for traffic, all PTGs in L2P1 will have the same neutron-ntk
	# i.e. self.reg_ptg,self.l2p1_autoptg = self.l2p1_ntkid

	    if self.reg_ptg and self.l2p1_autoptg and self.l2p2_autoptg:
	        self.ptgs = [self.reg_ptg, self.l2p1_autoptg, self.l2p1_autoptg,\
		         self.l2p2_autoptg]
	    else:
	        LOG.error(
		    "Cannot create PTs since some PTGs are not yet initialized"
		     )
	        return 0
            self.vms = GBPvms[tnt1]
	    self.ptlist = ['pt1','pt2','pt3','pt4']
	    for i in range(len(self.ptlist)):
	        pt = self.ptlist[i]
	        vm = self.vms[i]
	        ptg = self.ptgs[i]
	    #NOTE:First all 3 PTs/VMs belong to L2P1 BD
	        if i < 3:
		    if i == 0:
		       tag = 'intra_bd'
		    else:
		       tag = 'intra_epg'
		    ntk = self.l2p1_ntkid
	        else:
	    	    ntk = self.l2p2_ntkid
		    tag = 'inter_bd'
	        gbp_vm_ntk_ip[tnt][vm] = {'port' : self.gbptnt1.create_gbp_policy_target(
       			          pt, ptg, ptg_property='uuid')[1],
				'netns' : 'qdhcp-%s' %(ntk),
				'tag' : tag}
	if tnt == tnt2:
            LOG.info(
            "\n######################################################\n"
            "## Create Two Policy-Targets from an Auto-PTGs for Tenant %s\n"
            "########################################################\n"
	    %(tnt))
	    self.vms = GBPvms[tnt2]
	    for vm,pt in {self.vms[0]:'pt5',self.vms[1]:'pt6'}.iteritems():
	        gbp_vm_ntk_ip[tnt][vm] = {'port' : self.gbptnt2.create_gbp_policy_target(
						   pt,self.l2p3_autoptg,
						   ptg_property='uuid')[1],
					  'netns' : 'qdhcp-%s' %(self.l2p3_ntkid),
					  'tag' : 'intra_epg'
					}
	print gbp_vm_ntk_ip
	if 0 in gbp_vm_ntk_ip.values():
	    LOG.error("\nNot all PTs are created properly = %s"
                 %(gbp_vm_ntk_ip))
	    return 0
    def install_tenant_vms(self,tnt):
        LOG.info(
        "\n################################################\n"
        "## Create VMs for Tenant %s ##\n"
        "##################################################\n"
        %(tnt))
        az = neutron.alternate_az(AVZONE)
        for vm,prop in gbp_vm_ntk_ip[tnt].iteritems():
	    if tnt == tnt1:
                vm_ip = self.novatnt1.vm_create_api(vm,
                                      conf['vm_image'],
                                      prop['port'],
                                      avail_zone=az.next(),
                                      flavor_name=conf['vm_flavor'],
				      ret_ip = True)
	    if tnt == tnt2:
                vm_ip = self.novatnt2.vm_create_api(vm,
                                      conf['vm_image'],
                                      prop['port'],
                                      avail_zone=az.next(),
                                      flavor_name=conf['vm_flavor'],
				      ret_ip = True)
	    if not vm_ip:
                LOG.error("\n//// %s Create failed ////" %(vm))
                return 0
	    else:
		gbp_vm_ntk_ip[tnt][vm]['src_ip'] = vm_ip 
	print "VM_property after VM install == ",gbp_vm_ntk_ip

    def create_ext_seg(self,nattype):
        LOG.info(
        "\n########################################################\n"
        "## Create External Segment as shared under tenant-Admin ##\n"
        "##########################################################\n"
        )
	self.extsegid = {}
	if nattype == 'nat':
	    es_name = 'Management-Out'
	    extsub = create_external_network_subnets('nat')[0]
	if nattype == 'nonat': 
	    es_name = 'Datacenter-Out'
	    extsub = create_external_network_subnets('nonat')
        self.extsegid = self.gbpadmin.create_gbp_external_segment(
                                        es_name,
					subnet_id = extsub,
					external_routes = [{
                                           'destination':'0.0.0.0/0',
                                           'nexthop': None}],
				       	shared=True
                                       )
	    
        if self.extsegid == 0:
            LOG.error(
            "\nCreation of %s External Segment %s failed" %(nattype, es_name))
            return 0

    def create_ext_pol(self,tnt):
        LOG.info(
        "\n########################################\n"
        "## Create External Policy in tenant %s ##\n"
        "###########################################\n"
        %(tnt)) 
	if tnt == tnt1:
	    extpolname = 'MgmtExtPol'
	if tnt == tnt2:
	    extpolname = 'DcExtPol'
	gbptnt = GBPCrud(CNTRLIP,tenant=tnt)
	self.extpol = gbptnt.create_gbp_external_policy(
					extpolname,
					external_segments=[self.extsegid]
					)
	if self.extpol == 0:
            LOG.error(
            "\nCreation of External Policy failed")
            return 0

    def attach_l3p_extseg(self,tnt):
        LOG.info(
        "\n########################################################\n"
        "## Updating L3Policy in tenant %s to attach to ExtSegments ##\n"
        "##########################################################\n"
        %(tnt))
	if tnt == tnt1:
	    l3p = self.l2p1_impl3p
	if tnt == tnt2:
	    l3p = self.l3p_uuid
	gbptnt = GBPCrud(CNTRLIP,tenant=tnt)
	if gbptnt.update_gbp_l3policy(l3p,
					    property_type='uuid',
					    external_segments=self.extsegid
					    ) == 0:
            LOG.error(
	    "\nUpdating L3Policy to attach ExtSegment failed for Tenant %s"
	    %(tnt))
	    return 0

    def create_shared_contracts(self):
        LOG.info(
        "\n########################################################\n"
        "## Create shared contracts and related resources in tenant-Admin %s ##\n"
        "##########################################################\n"
        )
	#Create and Verify Policy-Action
        self.gbpadmin.create_gbp_policy_action(ACT,
                                             action_type='allow',
					     shared=True)
        self.actid = self.gbpadmin.verify_gbp_policy_action(ACT)
        if self.actid == 0:
            LOG.error(
		"\n Reqd Policy Action Create Failed")
            return 0
	#Create and Verify Policy-Classifier ICMP
        self.gbpadmin.create_gbp_policy_classifier(CLS_ICMP,
                                                  direction= 'bi',
                                                  protocol = 'icmp',
						  shared=True)
        self.clsicmpid = self.gbpadmin.verify_gbp_policy_classifier(CLS_ICMP)
        if self.clsicmpid == 0:
            LOG.error(
                "\nReqd ICMP Policy Classifier Create Failed")
            return 0
        #Create and Verify Policy-Rule ICMP
        self.gbpadmin.create_gbp_policy_rule(PR_ICMP,
                                            self.clsicmpid,
                                            self.actid,
                                            property_type = 'uuid',
					    shared=True)
        self.ruleicmpid = self.gbpadmin.verify_gbp_policy_rule(PR_ICMP)
        if self.ruleicmpid == 0:
            LOG.error(
                "\n## Reqd ICMP Policy Rule Create Failed")
            return 0
        # Create and Verify TCP Policy Classifier
        self.gbpadmin.create_gbp_policy_classifier(CLS_TCP,
                                                  direction= 'bi',
                                                  protocol = 'tcp',
                                                  port_range = '20:2000',
						  shared=True)
        self.clstcpid = self.gbpadmin.verify_gbp_policy_classifier(CLS_TCP)
        if self.clstcpid == 0:
            LOG.error(
                "\nReqd TCP Policy Classifier Create Failed")
            return 0
        # Create and Verify TCP Policy Rule
        self.gbpadmin.create_gbp_policy_rule(PR_TCP,
                                            self.clstcpid,
                                            self.actid,
                                            property_type = 'uuid',
					    shared=True)
        self.ruletcpid = self.gbpadmin.verify_gbp_policy_rule(PR_TCP)
        if self.ruletcpid == 0:
            LOG.error(
                "\n## Reqd TCP Policy Rule Create Failed")
            return 0
	self.prs_name_id = {}
        # Create and Verify ICMP-TCP Policy Rule Set
        self.gbpadmin.create_gbp_policy_rule_set(
                                        PRS_ICMP_TCP,
                                        rule_list=[
                                          self.ruleicmpid,
                                          self.ruletcpid
                                                ],
					shared=True,
                                        property_type = 'uuid')
        self.prsicmptcpid = self.gbpadmin.verify_gbp_policy_rule_set(PRS_ICMP_TCP)
        if self.prsicmptcpid == 0:
            LOG.error(
                "\n## Reqd ICMP-TCP Policy RuleSet Create Failed")
            return 0
	else:
	    self.prs_name_id[PRS_ICMP_TCP] = self.prsicmptcpid
        # Create and Verify ICMP Policy Rule Set
        self.gbpadmin.create_gbp_policy_rule_set(
                                        PRS_ICMP,
                                        rule_list=[self.ruleicmpid],
                                        property_type = 'uuid',
					shared=True
                                        )
        self.prsicmpid = self.gbpadmin.verify_gbp_policy_rule_set(PRS_ICMP)
        if self.prsicmpid == 0:
            LOG.error(
                "\n## Reqd ICMP Policy RuleSet Create Failed")
            return 0
	else:
	    self.prs_name_id[PRS_ICMP] = self.prsicmpid
        # Create and Verify TCP Policy Rule Set 
        self.gbpadmin.create_gbp_policy_rule_set(
                                        PRS_TCP,
                                        rule_list=[self.ruletcpid],
                                        property_type = 'uuid',
					shared=True
                                        )
        self.prstcpid = self.gbpadmin.verify_gbp_policy_rule_set(PRS_TCP)
        if self.prstcpid == 0:
            LOG.error(
                "\n## Reqd TCP Policy RuleSet Create Failed")
            return 0
	else:
	    self.prs_name_id[PRS_TCP] = self.prstcpid

    def update_intra_bd_ptg_by_contract(self,prs):
	prs = self.prs_name_id[prs]
	if self.gbptnt1.update_gbp_policy_target_group(
				self.reg_ptg,
				property_type='uuid',
				provided_policy_rulesets=[prs]
				) == 0 or \
	   self.gbptnt1.update_gbp_policy_target_group(
				self.l2p1_autoptg,
				property_type='uuid',
				consumed_policy_rulesets=[prs]
				) == 0:
		return 0

    def update_inter_bd_ptg_by_contract(self,prs):
	prs = self.prs_name_id[prs]
	if self.gbptnt1.update_gbp_policy_target_group(
				self.l2p2_autoptg,
				property_type='uuid',
				provided_policy_rulesets=[prs]
				) == 0:
		return 0
	for ptg in [self.reg_ptg,self.l2p1_autoptg]:
	    if self.gbptnt1.update_gbp_policy_target_group(
				ptg,
				property_type='uuid',
				consumed_policy_rulesets=[prs]
				) == 0:
		return 0
				
    def update_allptgs_by_contract_for_extraff(self,prs):
	prs = self.prs_name_id[prs]
	if self.gbptnt1.update_gbp_external_policy(
				self.extpol,
				property_type='uuid',
				consumed_policy_rulesets=[prs]
				) == 0:
		return 0
	for ptg in [self.reg_ptg,
                    self.l2p1_autoptg,
		    self.l2p2_autoptg]:
	    if self.gbptnt1.update_gbp_policy_target_group(
				ptg,
				property_type='uuid',
				consumed_policy_rulesets=None,
				provided_policy_rulesets=[prs]
				) == 0:
		return 0

    def update_ptg_extptg_nonat_traff(self,prs):
	prs = self.prs_name_id[prs]
	if self.gbptnt2.update_gbp_external_policy(
				self.extpol,
				property_type='uuid',
				consumed_policy_rulesets=[prs]
				) == 0:
		return 0
	if self.gbptnt2.update_gbp_policy_target_group(
				self.l2p3_autoptg,			
				property_type='uuid',
				consumed_policy_rulesets=None,
				provided_policy_rulesets=[prs]
				) == 0:
		return 0

    def cleanup_gbp(self):
	for tnt in TNT_LIST_GBP:
	    #Delete VMs for a given ML2 tenant
	    for vm in GBPvms[tnt]:
	        neutron.runcmd(
		'nova --os-tenant-name %s delete %s' %(tnt,vm))
	    #Delete FIPs
	    try:
	        if GBPFips:
		    for fip in GBPFips[tnt]:
		        neutron.runcmd(
		        'nova --os-tenant-name %s floating-ip-delete %s'
 			 %(tnt,fip))
            except Exception:
                print 'FIPs do not exist for ',tnt
                pass
	    try:
		gbpclean = GBPCrud(CNTRLIP,tenant=tnt)
                pt_list = gbpclean.get_gbp_policy_target_list()
            	if len(pt_list):
              	    for pt in pt_list:
                    	gbpclean.delete_gbp_policy_target(pt, property_type='uuid')
           	ptg_list = gbpclean.get_gbp_policy_target_group_list()
           	if len(ptg_list):
              	    for ptg in ptg_list:
                	gbpclean.delete_gbp_policy_target_group(ptg, property_type='uuid')
           	l2p_list = gbpclean.get_gbp_l2policy_list()
           	if len(l2p_list):
              	    for l2p in l2p_list:
                 	gbpclean.delete_gbp_l2policy(l2p, property_type='uuid')
           	l3p_list = gbpclean.get_gbp_l3policy_list()
           	if len(l3p_list) :
                   for l3p in l3p_list:
                 	gbpclean.delete_gbp_l3policy(l3p, property_type='uuid')
           	gbpclean.delete_gbp_network_service_policy()
           	natpool_list = gbpclean.get_gbp_nat_pool_list()
           	if len(natpool_list) :
              	    for natpool in natpool_list:
                 	gbpclean.delete_gbp_nat_pool(natpool)
           	extpol_list = gbpclean.get_gbp_external_policy_list()
           	if len(extpol_list) :
              	    for extpol in extpol_list:
                 	gbpclean.delete_gbp_external_policy(extpol)
           	extseg_list = gbpclean.get_gbp_external_segment_list()
           	if len(extseg_list) :
              	    for extseg in extseg_list:
                 	gbpclean.delete_gbp_external_segment(extseg)
           	prs_list = gbpclean.get_gbp_policy_rule_set_list()
        	if len(prs_list) > 0:
           	    for prs in prs_list:
               		gbpclean.delete_gbp_policy_rule_set(
				   prs, property_type='uuid')
        	pr_list = gbpclean.get_gbp_policy_rule_list()
        	if len(pr_list) > 0:
           	    for pr in pr_list:
               		gbpclean.delete_gbp_policy_rule(
					pr, property_type='uuid')
        	cls_list = gbpclean.get_gbp_policy_classifier_list()
        	if len(cls_list) > 0:
           	    for cls in cls_list:
               		gbpclean.delete_gbp_policy_classifier(
					cls, property_type='uuid')
        	act_list = gbpclean.get_gbp_policy_action_list()
        	if len(act_list) > 0:
           	    for act in act_list:
               		gbpclean.delete_gbp_policy_action(
				act, property_type='uuid')
	    except Exception as e:
		print "Exception in Cleanup == ", repr(e)
		pass
	    neutron.runcmd('neutron subnetpool-delete %s' %(gbp_nonat_sps))
	    neutron.runcmd('neutron address-scope-delete %s' %(gbp_nonat_ads))
	    neutron.runcmd('neutron net-delete Management-Out')
	    neutron.runcmd('neutron net-delete Datacenter-Out')
	return 1

class verifyML2(object):
      def __init__(self):
	return 1


class sendTraffic(object):
    #Ensure to inherit/instantiate the class after 
    #all VMs are created
    def generate_vm_prop(self,tnt,ext=False):
	print 'VM_to_NTK_IP inside Traffic Class for == ', ml2_vm_ntk_ip[tnt]
  	properties = {}
	for vm,prop in ml2_vm_ntk_ip[tnt].iteritems():
	    if ext:
	        pingable_ips = [ip for val in ml2_vm_ntk_ip[tnt].values() for ip in val][0::2]+\
                    [EXTRTRIP1,EXTRTRIP2]
	    else:
	        pingable_ips = [ip for val in ml2_vm_ntk_ip[tnt].values() for ip in val][0::2]
	    pingable_ips.remove(prop[0]) #Removing the Src_IP from the list of pingable_ips
	    dest_ips = pingable_ips
	    properties[vm] = {'netns' : 'qdhcp-'+prop[1],
			      'src_ip' : prop[0],
			      'dest_ip' : dest_ips
			     }
	return properties
	
    def traff_from_ml2_tenants(self,tnt,ext=False,proto=['icmp','tcp','metadata']):
	LOG.info(
        "\n#############################################\n"
        "## Sending Traffic from VMs in ML2-tenant %s ##\n"
        "###############################################\n"
        %(tnt))
	tenant_vms  = ML2vms[tnt]
	vm_property = self.generate_vm_prop(tnt,ext=ext)
	print "VM Properties == ", vm_property
	for vm in tenant_vms:
	    vm_traff = traffic_class(COMPUTE1,vm_property[vm]['netns'],
				vm_property[vm]['src_ip'],
				vm_property[vm]['dest_ip'])
	    if not vm_traff.run_and_verify_traffic(proto,tcp_syn_only=1):
	    	return 0

    def get_epg_vms(self,tnt,tag):
	"""
	The intent of this method is to return a dict of VMs
	based on their EPG or BD locations
	"""
	epg_vms = {}
	if tag == 'intra_epg':
	    for vm,prop in gbp_vm_ntk_ip[tnt].iteritems():
		#NOTE: pingable IPs are ONLY the VM_IPs in the same EPG
		pingable_ips = [val['src_ip'] for val in gbp_vm_ntk_ip[tnt].values() if val['tag'] == tag]
	        if prop['tag'] == tag:
		    pingable_ips.remove(prop['src_ip'])
		    prop['dest_ip'] = pingable_ips
		    epg_vms[vm] = prop
	    return epg_vms	    
	if tag == 'intra_bd':
	    for vm,prop in gbp_vm_ntk_ip[tnt].iteritems():
		#NOTE: pingable IPs are ONLY the VM_IPs in the same BD
		pingable_ips = [val['src_ip'] for val in gbp_vm_ntk_ip[tnt].values() if val['tag'] == 'intra_epg' or 'intra_bd']
	        if prop['tag'] == tag:
		    pingable_ips.remove(prop['src_ip'])
		    prop['dest_ip'] = pingable_ips
		    epg_vms[vm] = prop
	    return epg_vms	    
	if tag == 'inter_bd': 
	    #NOTE: pingable IPs are all the VM_IPs in the same 
	    for vm,prop in gbp_vm_ntk_ip[tnt].iteritems():
		pingable_ips = [val['src_ip'] for val in gbp_vm_ntk_ip[tnt].values()]
	        if prop['tag'] == tag:
		    pingable_ips.remove(prop['src_ip'])
		    prop['dest_ip'] = pingable_ips
		    epg_vms[vm] = prop
	    return epg_vms	    
		 
    def traff_from_gbp_tenant(self,tnt,traffic_type,ext=False,
				proto=['icmp','tcp','metadata']
				):
	LOG.info(
        "\n#############################################\n"
        "## Sending Traffic from VMs in GBP-tenant %s ##\n"
        "###############################################\n"
        %(tnt))
	# valid strings for traffic_type:: 'inter_bd', 'intra_bd', 'intra_epg'
	test_vms = self.get_epg_vms(tnt,traffic_type)
	print 'After EPG based classification of VMs ', test_vms	
	for vm,vm_property in test_vms.iteritems():
	    if ext:
		target_ips = [EXTRTRIP1,EXTRTRIP2]
	    else:
		target_ips = vm_property['dest_ip']
	    print "Target IPs for the VM ", vm, target_ips
	    vm_traff = traffic_class(COMPUTE1,vm_property['netns'],
				vm_property['src_ip'],
				target_ips)
	    if not vm_traff.run_and_verify_traffic(proto,tcp_syn_only=1):
		#Sleep for 5s and re-run traffic again
		sleep(5)
		if not vm_traff.run_and_verify_traffic(proto,tcp_syn_only=1):
	            return 0
	
    def traff_from_extrtr_to_fips(self,mode,tnt):
        """
        Ping and TCP test from external router to VMs
        """
	LOG.info(
        "\n#############################################\n"
        "## Sending ICMP/TCP Traffic from EXT-RTR to VMs ##\n"
        "###############################################\n"
        )
	if mode == 'ml2':
	    fips = ML2Fips[tnt]
	else:
	    fips = GBPFips[tnt]
	print "Target FIPs for the EXT-RTR", fips
        run_traffic = traff_from_extgwrtr(
                                          EXTRTR,
                                          fips
                                          )
        if isinstance(run_traffic, dict):
	    #Sleep for 5s and re-run traffic again
	    sleep(5)
	    if isinstance(run_traffic, dict):
                return 0




