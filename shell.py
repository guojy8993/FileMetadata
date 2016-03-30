#! /usr/bin/python
# -*- coding:utf-8 -*-

import time
import re
import sys
import os
import logging
import json
import uuid
from wsgiref.simple_server import make_server
 
reserved_http_method="POST"			       # http method allowd
reserved_source_ip=("10.160.0.108","10.100.0.192")     # client-ips allowed

shell_dir="/opt/shells/"                               # directory storing received-scripts
server_port=9998				       # port metadata-server listens to. 


logs="/var/log/server.log"

logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s",
	datefmt="%a, %d %b %Y %H:%M:%S",
	filename=logs,
        filemode="a"
)

def printShell(shell):
	fmt = "%(path)sshell_%(time)s_%(randstr)s"
	_randstr = str(uuid.uuid4())
	filename = fmt % { 
			    "path":shell_dir,
			    "randstr":_randstr,
			    "time":time.strftime('%Y-%m-%d-%X',time.localtime(time.time()))
	}
	f = open(filename,"w" if os.path.exists(filename) else "a")
	f.write(shell)
	return filename

def application(environ,start_response):
	source_ip = environ['REMOTE_ADDR']
    	request_method = environ['REQUEST_METHOD']
        logging.info("Client %s trying to access service." % source_ip)	
         	  	 
	if not source_ip in reserved_source_ip:
                status = '401 Unauthorized'
                headers = [('Content-type', 'application/json')]
                start_response(status, headers)
                return ['Unauthorized']
        
	if request_method != reserved_http_method:
        	status = '405 Method Not Allowed'
        	headers = [('Content-type', 'application/json')]
        	start_response(status, headers)
        	return ['Method Not Allowed']
        		
	request_body_size = int(environ.get('CONTENT_LENGTH', 0))
	request_body = environ['wsgi.input'].read(request_body_size)	
	try:
		shell_path = None
		if request_body_size > 0:
			shell_path = printShell(request_body)
		else:
			raise Exception("No scripts received.")
		cmdline = "/bin/bash %s" % shell_path
		exit_code = os.system(cmdline)
		logging.info("Exec cmdline '%s' and exit-code '%d' received." % (cmdline,exit_code/256))
		result = {"code":exit_code/256}
			
		status = '200 OK'
        	headers = [('Content-type', 'application/json')]
        	start_response(status, headers)
		
		return ['%s' % json.dumps(result)]

	except Exception as e:
        	status = '400 Bad Request'
        	headers = [('Content-type', 'application/json')]
        	start_response(status, headers)
		return ['%s' % e]

def start_server():
	if not os.path.exists(shell_dir):
		os.mkdir(shell_dir)
	server = make_server('',server_port,application)
	server.serve_forever()
	

if __name__ == "__main__":
	start_server()





























