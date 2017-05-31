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

import sys
import logging
import re
import yaml
from time import sleep
from gbp_utils import *
from fabric.contrib import files

# Initialize logging
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s - %(message)s', level=logging.WARNING)
_log = logging.getLogger( __name__ )

_log.setLevel(logging.INFO)
_log.setLevel(logging.DEBUG)

class gbpHeat(object):

    def __init__(self, controllerIp, cntrlr_uname='root', cntrlr_passwd='noir0123', tenant='admin'):
        self.cntrlrip = controllerIp
        self.username = cntrlr_uname
        self.password = cntrlr_passwd
        self.tenant = tenant
        self.err_strings=['Unable','Conflict','Bad Request','Error', 'Unknown','Exception','ERROR']

    def run_heat_cli(self,cmd):
        """
        Heat Cli
        """
        return run_openstack_cli([cmd],self.cntrlrip,
                                     username=self.username,
                                     passwd=self.password)
        
    def cmd_error_check(self,cmd_out):
        """
        Verifies whether executed cmd has any known error string
        """
        for err in self.err_strings:
            if re.search('\\b%s\\b' %(err), cmd_out, re.I):
               _log.info("Cmd execution failed! with this Return Error: \n%s" %(cmd_out))
               return 0
 
    def cfg_all_cli(self,val,name,heat_temp='',tenant='',upload=False, parameter_args=None):
        """
        Function to create/delete a pre-defined Heat Template
        -parma val : 0 for delete, 1 for create
        """
        if not tenant:
           tenant = self.tenant
        cmd_ver = "heat --os-tenant-name %s stack-show %s" %(tenant,name)
        if val ==1: ## Create & Verify Stack
	    if upload:
                upload_files(self.cntrlrip,
                             self.username,
                             self.password,
                             heat_temp,
                             '~/')
            cmd_cfg = "heat --os-tenant-name %s stack-create -f %s "\
                     %(tenant,heat_temp)+ name
            if parameter_args:
                cmd_cfg += parameter_args
            cfg_out = self.run_heat_cli(cmd_cfg)
            if not cfg_out:
               return 0
            _log.info("Sleeping for 10 secs ... to check if stack create completed")
            sleep(10) 
            num_try = 1
            cmd_out = self.run_heat_cli(cmd_ver)
            if not cmd_out:
               return 0
            while num_try > 0:
                if cmd_out.find('CREATE_COMPLETE') != -1:
                   return 1
                elif cmd_out.find('CREATE_FAILED') != -1:
		      _log.info("Heat Stack Create Failed, bailing out")
		      return 0
		else:
                    _log.info("Keep Retrying every 5s to check if heat stack-create completed")
                    sleep(5)
                    cmd_out = self.run_heat_cli(cmd_ver)
                if num_try > 50:
                    _log.info(" After 50 re-tries, the stack create has NOT COMPLETED")
                    return 0
                num_try +=1
        if val == 0:
           # First verify if the stack exists
           ver_out = self.run_heat_cli(cmd_ver)
           if not ver_out:
              _log.info("The stack does not exist, so no need of delete")
              return 1 
           # Else then proceed with delete as the said stack exists
           ostack_version = self.run_heat_cli('nova-manage version')
	   if ostack_version.find('2015') == 0 or ostack_version.find('2014') == 0:
    	      cmd_cfg = "heat --os-tenant-name %s stack-delete %s" %(tenant,name)
           else:
              cmd_cfg = "heat --os-tenant-name %s stack-delete %s -y"\
                        %(tenant,name)
           cfg_out = self.run_heat_cli(cmd_cfg)
           _log.info("Sleeping for 10 secs ... to check if stack got deleted")
           sleep(10)
           ver_out = self.run_heat_cli(cmd_ver)
           if not ver_out:
               return 1
           else:    
               num_try = 1
               while num_try > 0 :
                     ver_out = self.run_heat_cli(cmd_ver)
                     if not ver_out:
                        break
                     else:
                        _log.info("Keep waiting every 5s to verify if heat stack-delete completed")
                        sleep(5)
                        num_try +=1
                     if num_try > 30:
                        _log.info(" After 30 re-tries, the stack delete has still NOT COMPLETED")
                        return 0
               return 1

    def get_output_cli(self,stack_id_name,template_file):
        """
        Get the UUID of the created objects defined heat temp's Output Section
        - stack_id_name : Pass stack name or UUID
        """
        in_file = template_file
        f = open(in_file,'rt')
        heat_conf = yaml.load(f)
        _outputs = heat_conf["outputs"]
        objs_uuid = {}
        for key in _outputs.iterkeys():
            cmd = 'heat output-show %s %s' %(stack_id_name,key)
            cmd_out = self.run_heat_cli(cmd)
            #print cmd_out
            if not cmd_out:
               return None
            objs_uuid[key] = cmd_out
        return objs_uuid

    def get_uuid_from_stack(self,heat_templ_file,heat_stack_name):
        """
        Fetches the UUID of the GBP Objects created by Heat
        """
        path = path='../'
        for root,dirs,files in os.walk(path):
            if heat_templ_file in files:
	        yaml_file = os.path.join(root, heat_templ_file)
        with open(yaml_file,'rt') as f:
           heat_conf = yaml.load(f)
        obj_uuid = {}
        outputs_dict = heat_conf["outputs"]
        # This comprise dictionary with keys as in [outputs] block
        # of yaml-based heat template
        #print outputs_dict
        for key in outputs_dict.iterkeys():
            cmd = 'heat stack-show %s | grep -B 2 %s' %(heat_stack_name,key)
            cmd_out = self.run_heat_cli(cmd)
            if cmd_out:
                match = re.search('\"\\boutput_value\\b\": \"(.*)\"' ,cmd_out,re.I)
                if match != None:
                   obj_uuid[key] = match.group(1)
        return obj_uuid
