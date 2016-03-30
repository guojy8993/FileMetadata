#! /usr/bin/python
# -*- coding:utf-8 -*-

import time
import re
import sys
import os
import logging
import json
from wsgiref.simple_server import make_server
from pymongo import MongoClient
 
reserved_http_method="POST"			       # http method allowd
reserved_source_ip=("10.160.0.108","10.100.0.192")     # client-ips allowed
host="127.0.0.1"                                       # Mongodb Host
port=27017				               # port mongod listens to. 27017 ,by default
						       # `db` is just same as Gainet CloudStorage user 

logs="/var/log/metadata_server.log"                    # access log
server_port=9999				       # port metadata-server listens to. 

api_actions=(
	      "test", 
	      "add_metadata",			       # add                           
	      "del_metadata",			       # delete
              "update_metadata",		       # update 
	      "get_metadata",                          # get a metadata record
	      "calc_capacity")                         # calculate used-capacity in BUCKET


DEFAULT_METADATA_COLLECTION="test"                     # default table in db `bucket` that records file metadatas
ALLOWED_FILE_MODE=( 1,                                 # Private
		    2,				       # Public Read
                    3 )				       # Public Read/Write
DEFAULT_FILE_MODE=1				       # If file mode not specified, PRIVATE(1),by default 
RESULT_CODE_SUCCESS=1				       # 1 success
RESULT_CODE_FAIL=0				       # 0 fail


""" Metadate Properties Validators"""
def check_file_md5(**metadata):
	if "file_md5" not in metadata  or not valid_md5(metadata["file_md5"]):
        	raise Exception("API params error: file_md5 invalid ")

def check_filename(**metadata):
	if "filename" not in metadata or len(metadata["filename"]) == 0:
                raise Exception("API params error: file_name invalid ")

def check_created_at(**metadata):
	if "created_at" not in metadata:
        	metadata.update({"created_at":time.strftime('%Y-%m-%d %X',time.localtime(time.time()))})
        elif not valid_time(metadata["created_at"]):
        	raise Exception("API params error: created_at invalid,e.g:'2020-01-01 00:00:00'. ")

def check_filemode(**metadata):
	if "filemode" not in metadata:
		metadata.update({"filemode":DEFAULT_FILE_MODE})
	elif not isinstance(metadata["filemode"],int) or metadata["filemode"] not in ALLOWED_FILE_MODE:
                raise Exception("API params error: filemode invalid(1 for private,2 for public read and 3 for public rw)")

def check_sizeInByte(**metadata):
	if "sizeInByte" not in metadata or not isinstance(metadata["sizeInByte"],int) or metadata["sizeInByte"] < 0:
		raise Exception("API params error: sizeInByte invalid .")        

def check_path_hash(**metadata):
	if "path_hash" not in metadata or not valid_hash(metadata["path_hash"]):
        	raise Exception("API params error: path_hash  invalid,e.g:'242d5a1c-eca3-4d13-9d35-d488deb25838'. ")

def check_updated_at(**metadata):
	if "updated_at" not in metadata:
        	metadata.update({"updated_at":time.strftime('%Y-%m-%d %X',time.localtime(time.time()))})
        elif not valid_time(metadata["updated_at"]):
                raise Exception("API params error: updated_at invalid,e.g:'2020-01-01 00:00:00'. ")
      
def check_full_path(**metadata):
	if "full_path" not in metadata or metadata["full_path"] is None or len(metadata["full_path"]) == 0:
        	raise Exception("API params error: full_path invalid,it's should be some directory.")

def check_isdir(**metadata):
	if "isdir" not in metadata or not isinstance(metadata["isdir"],int) or metadata["isdir"] not in (0,1):
        	raise Exception("API params error: isdir invalid,e.g: 0 for file,1 for directory.")

""" Metadata properties and corresponding validators """
METADATA_PROP_VALIDATOR_MAPPING={
	"file_md5":"check_file_md5",
	"filename":"check_filename",
	"created_at":"check_created_at",
	"full_path":"check_full_path",
	"sizeInByte":"check_sizeInByte",
	"path_hash":"check_path_hash",
	"updated_at":"check_updated_at",
	"filemode":"check_filemode",
	"isdir":"check_isdir"
}

RESULT_CODE_SUCCESS=1
RESULT_CODE_FAIL=0

class API(object):
	def __init__(self,db):
		self.mongoClient = MongoClient(host=host,port=port)
		self.db = self.mongoClient.get_database(db)
		self.coll = self.db.get_collection(DEFAULT_METADATA_COLLECTION)

	def test(self,**args):
		path_hash = args["path_hash"]
		ishash = valid_hash(path_hash) 
		date_str = args["created_at"]
		isdate = valid_time(date_str) 
		file_md5 = args["file_md5"]
		match = valid_md5(file_md5)
		return {"name":"metadata","version":"0.1","match":match,"isdate":isdate,"ishash":ishash}

	def add_metadata(self,**args):
		if "metadata" not in args or args["metadata"] is None or not isinstance(args["metadata"],dict):
			raise Exception("API params incomplete.")
		metadata = args["metadata"]
		if len(metadata.keys()) <> len(METADATA_PROP_VALIDATOR_MAPPING.keys()):
		 	raise Exception("API params error: there exists non-metadata-property data.")
		for prop,validator in METADATA_PROP_VALIDATOR_MAPPING.iteritems():
			if prop not in metadata:
				raise Exception("API param 'metadata' incomplete.")
			if validator is not None and len(validator) > 0:
				eval(validator)(**metadata)
		logging.info("ADD_METADATA: %s " % metadata)
		try:
			self.coll.insert_one(metadata)
			return {"code":RESULT_CODE_SUCCESS}	
		except Exception as e:		
			return {"code":RESULT_CODE_FAIL}

	def del_metadata(self,**args):

	        if "filter" not in args or args["filter"] is None or not isinstance(args["filter"],dict):
			raise Exception("API params incomplete")
		filter = args["filter"]
		
		""" ensure no dirty data """
		if len(set(filter.keys()) - set(METADATA_PROP_VALIDATOR_MAPPING.keys())) > 0 or len(filter.keys()) <> 3:
			raise Exception("API params error: there exists non-metadata-property data.")
		
		""" `full_path` and `filename`,`isdir` are required  """
		check_full_path(**filter)
		check_filename(**filter)
		check_isdir(**filter)

		""" delete records matching del_condition """
		del_conditions = {}
		if filter["isdir"] == 1:
			OR_LIST = []
			""" match all child files existing in this directory """
			subfiles = "%s%s%s\\S{0,}" % (filter["full_path"],filter["filename"],os.sep)
			
			OR_LIST.append({"full_path":{"$regex":subfiles}})
			"""
			`Conditions`(matching childs) OR `Conditions`(match current directory)
			"""
			OR_LIST.append(filter)
			del_conditions["$or"] = OR_LIST 					
		else:
			del_conditions.update(filter)	

		logging.info("DELETE_METADATA: drop records that satisfy conditions %s " % del_conditions)
		try:
			self.coll.delete_many(del_conditions)
			return {"code":RESULT_CODE_SUCCESS}
		except Exception as e:
			return {"code":RESULT_CODE_FAIL}	
		
	
	def update_metadata(self,**args):

		if "filter" not in args or args["filter"] is None or not isinstance(args["filter"],dict):
                        raise Exception("API params incomplete")
                filter = args["filter"]
		if len(set(filter.keys()) - set(METADATA_PROP_VALIDATOR_MAPPING.keys())) > 0 or len(filter.keys()) <> 3:
                        raise Exception("API params error: there exists non-metadata-property data.")			
		
		check_full_path(**filter)
                check_filename(**filter)
                check_isdir(**filter)

		if "update" not in args or args["update"] is None or not isinstance(args["update"],dict):
                        raise Exception("API params incomplete")
                update = args["update"]
		if len(set(update.keys()) - set(METADATA_PROP_VALIDATOR_MAPPING.keys())) > 0 or len(update.keys()) <> 1:
                        raise Exception("API params error: there exists non-metadata-property data.")
			
		check_filemode(**update)

		update_conditions = {}
                if filter["isdir"] == 1:
                        OR_LIST = []
                        """ match all child files existing in this directory """
                        subfiles = "%s%s%s\\S{0,}" % (filter["full_path"],filter["filename"],os.sep)

                        OR_LIST.append({"full_path":{"$regex":subfiles}})
                        """
                        `Conditions`(matching childs) OR `Conditions`(match current directory)
                        """
                        OR_LIST.append(filter)
                        update_conditions["$or"] = OR_LIST
                else:
                        update_conditions.update(filter)
		now_str = time.strftime('%Y-%m-%d %X',time.localtime(time.time()))
		update.update({"updated_at":now_str})
		update = {"$set":update}
		
		logging.info("UPDATE_METADATA: update records that satisfy conditions %s to value %s " % (update_conditions,update))
                try:
                        self.coll.update_many(update_conditions,update)
                        return {"code":RESULT_CODE_SUCCESS}
                except Exception as e:
                        return {"code":RESULT_CODE_FAIL}			

	def get_metadata(self,**args):
	  	if "filter" not in args or args["filter"] is None or not isinstance(args["filter"],dict):
                        raise Exception("API params incomplete")
                filter = args["filter"]
                if len(set(filter.keys()) - set(METADATA_PROP_VALIDATOR_MAPPING.keys())) > 0 or len(filter.keys()) <> 3:
                        raise Exception("API params error: there exists non-metadata-property data.")
                check_full_path(**filter)
                check_filename(**filter)
                check_isdir(**filter)
		filter_conditions = {}
                if filter["isdir"] == 1:
                        OR_LIST = []
                        """ match all child files existing in this directory """
                        subfiles = "%s%s%s\\S{0,}" % (filter["full_path"],filter["filename"],os.sep)

                        OR_LIST.append({"full_path":{"$regex":subfiles}})
                        """
                        `Conditions`(matching childs) OR `Conditions`(match current directory)
                        """
                        OR_LIST.append(filter)
                        filter_conditions["$or"] = OR_LIST
                else:
                        filter_conditions.update(filter)

		logging.info("GET_METADATA: get metadata records matching conditions %s " % filter_conditions)
		cursor = None
		try:
			cursor = self.coll.find(filter_conditions)
		except Exception as e:
			return {"code":RESULT_CODE_FAIL}
		
		""" Iterate the cursor to get Metadata object """
		result = []
		for i in xrange(cursor.count()):
			item = cursor.next()
			del item["_id"]
			"""
			for some confusing reason, `isdir` and `sizeInByte`,`filemode` are output as `float` type , not `int`
			here lets do some handling
			"""
			if str(item["filemode"]).endswith(".0"):
                                item.update({"filemode":int(str(item["filemode"])[:-2])})
			if str(item["isdir"]).endswith(".0"):
				item.update({"isdir":int(str(item["isdir"])[:-2])})
			if str(item["sizeInByte"]).endswith(".0"):
                                item.update({"sizeInByte":int(str(item["sizeInByte"])[:-2])})
			result.append(item)
		return {"code":RESULT_CODE_SUCCESS,"result":result}

		

	def calc_capacity(self,**args):
		if "filter" not in args or args["filter"] is None or not isinstance(args["filter"],dict):
                        raise Exception("API params incomplete")
                filter = args["filter"]
                if len(set(filter.keys()) - set(METADATA_PROP_VALIDATOR_MAPPING.keys())) > 0 or len(filter.keys()) <> 3:
                        raise Exception("API params error: there exists non-metadata-property data.")

                check_full_path(**filter)
                check_filename(**filter)
                check_isdir(**filter)
                filter_conditions = {}
                if filter["isdir"] == 1:
                        OR_LIST = []
                        """ match all child files existing in this directory """
                        subfiles = "%s%s%s\\S{0,}" % (filter["full_path"],filter["filename"],os.sep)

                        OR_LIST.append({"full_path":{"$regex":subfiles}})
                        """
                        `Conditions`(matching childs) OR `Conditions`(match current directory)
                        """
                        OR_LIST.append(filter)
                        filter_conditions["$or"] = OR_LIST
                else:
                        filter_conditions.update(filter)
		group_sum = {"$group":{"_id":None,"size":{"$sum":"$sizeInByte"}}}
		match = {"$match":filter_conditions}
		pipe = []
		pipe.append(match)
		pipe.append(group_sum)
		result = None
		try:
			result = self.db.command("aggregate",DEFAULT_METADATA_COLLECTION,pipeline=pipe)
		except Exception as e:
			return {"code":RESULT_CODE_FAIL}
		if result is not None and len(result["result"]) == 1:
			capacity = result["result"][0]["size"]
			if str(capacity).endswith(".0"):
				capacity = int(str(capacity)[:-2])
			return {"code":RESULT_CODE_SUCCESS,"capacity":capacity}
		else:
			return {"code":RESULT_CODE_SUCCESS,"capacity":0}
		
		

def filter_unicode(uniformat_str):
	q = re.findall(r"(\u[0-9a-f]{4})+",uniformat_str)
	for i in q:
        	z = ("\%s"%i).decode("unicode_escape")
        	uniformat_str = uniformat_str.replace("\%s"%i,z)
	return uniformat_str

def valid_hash(hash_str):
        if hash_str is None or len(hash_str) <> 36:
        	return False	
	result = re.match(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",hash_str)
	return result is not None

def valid_time(time_str):
	if time_str is None or len(time_str) <> 19:
		return False
	result = re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",time_str)
        return result is not None	 

def valid_md5(md5_str):
	if md5_str is None or len(md5_str) <> 32:
		return False
	result = re.match(r"[a-f0-9]{32}",md5_str)
	return result is not None

def init_log():
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s",
		datefmt="%a, %d %b %Y %H:%M:%S",
		filename=logs,
		filemode="a"
	)
def application(environ,start_response):
	source_ip = environ['REMOTE_ADDR']
    	request_method = environ['REQUEST_METHOD']
        logging.info("Client %s trying to access service." % source_ip)	
        
	if not source_ip in reserved_source_ip:
                status = '401 Unauthorized'
                headers = [('Content-type', 'application/json')]
                start_response(status, headers)
                return ['{"msg":"Unauthorized"}']
        
	if request_method != reserved_http_method:
        	status = '405 Method Not Allowed'
        	headers = [('Content-type', 'application/json')]
        	start_response(status, headers)
        	return ['{"msg":"Method Not Allowed"}']
	
	request_body_size = int(environ.get('CONTENT_LENGTH', 0))
	request_body = environ['wsgi.input'].read(request_body_size)
	logging.info(request_body)
		
	try:
		request_body = json.loads(request_body)
		if "action" not in request_body or "account" not in request_body:
			raise Exception("API params incomplete.")
		action = request_body.pop("action")
		db = request_body.pop("account")
		if action in api_actions:
			result = getattr(API(db=db),action)(**request_body)
			status = '200 OK'	
			headers = [('Content-type', 'application/json')]
			start_response(status, headers)
			result = {"result":result}
			response = json.dumps(result)
			""" do some coding-transform work """
			response = filter_unicode(response).encode("UTF-8")
                	return ['%s'%response]
		else:
			raise Exception("API method '%s' not implemented " % action)
	except Exception as e:
        	status = '400 Bad Request'
        	headers = [('Content-type', 'application/json')]
        	start_response(status, headers)
		return ['%s' % e]

def start_server():
	init_log()
        logging.info("Starting metadata server ...")	
	metadata_server = make_server('',server_port,application)
	logging.info("Metadata server starts listening to 127.0.0.1:%d"%server_port)	
	metadata_server.serve_forever()
	

if __name__ == "__main__":
	start_server()





























