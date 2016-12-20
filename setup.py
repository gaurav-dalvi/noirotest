#!/usr/bin/env python  
import sys
from fabric.api import cd, run, env, hide, get, settings, local ,put
from fabric.context_managers import *

def main():
    controller_ip = sys.argv[1]
    apic_ip = sys.argv[2]
    setup(controller_ip,apic_ip)

def setup(controller_ip,apic_ip,cntlr_user='root',apic_user='admin',
          apic_pwd = 'noir0123', cntlr_pwd='noir0123'):

    env.host_string = controller_ip
    env.user = cntlr_user
    env.password = cntlr_pwd
    
    #Step-1: Copy the Heat Templates to the Controller
    for heat_templt in ['~/noirotest_local/testcases/heat_temps/heat_dnat_only.yaml',
			'~/noirotest_local/testcases/heat_temps/heat_snat_only.yaml',
			'~/noirotest_local/testcases/heat_temps/preexist_dnat_only.yaml',
			'~/noirotest_local/testcases/heat_temps/preexist_snat_only.yaml',
			'~/noirotest_local/testcases/heat_temps/heat_tmpl_regular_dp_tests.yaml'
			'add_ssh_filter.py'
			]:
         put(heat_templt,'~/')
    #Step-2: Restart the below services
    for cmd in ['systemctl restart openstack-nova-api.service',
		'systemctl restart openstack-nova-scheduler.service',
		'systemctl restart openstack-heat-engine.service',
		'systemctl restart openstack-heat-api.service'
               ]:
       run(cmd)

    #Step-3: Update the Nova-quotas and Enable ACI Route-reflector
    with settings(warn_only=True):
        os_flvr = run('cat /etc/os-release')
        if 'Red Hat' in os_flvr:
            cmd_src = 'source /root/keystonerc_admin'
	if 'Ubuntu' in os_flvr:
            cmd_src = 'source ~/openrc'
        rr_cmd = 'apic route-reflector-create --ssl --no-secure '+\
                 '--apic-ip %s --apic-username %s --apic-password %s' %(apic_ip,apic_user,apic_pwd)
	with prefix(cmd_src):
            for cmd in ['nova quota-class-update --instances -1 default',
			'nova quota-class-update --ram -1 default',
			'nova quota-class-update --cores -1 default',
			'nova quota-show',
                        rr_cmd]:
		run(cmd)

if __name__ == "__main__":
    main()
    