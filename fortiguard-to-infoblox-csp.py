import requests
import base64
import json
import re
import math
import logging
import time
import gzip
import ipaddress
import urllib
import ssl

#########################################################			
logging.basicConfig(handlers = [logging.FileHandler('fortiguard-to-infoblox-csp.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

tide_apikey = ''
csp_apikey  = ''
fortiguard_apikey= ''
use_already_downloaded_IOC_files = False

#########################################################

def is_fqdn(hostname):
    """
    :param hostname: string
    :return: bool
    """
    #  Remove trailing dot
    try:  # Is this necessary?
        if hostname[-1] == '.':
            hostname = hostname[0:-1]
    except IndexError:
        return False

    #  Check total length of hostname < 253
    if len(hostname) > 253:
        return False

    #  Split hostname into list of DNS labels
    hostname = hostname.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

    #  Check if length of each DNS label < 63
    #  Match DNS label to pattern
    for label in hostname:
        if len(label) > 63:
            return False
        if not fqdn.match(label):
            return False

    #  Found no errors, returning True
    return True
    
#########################################################

def getTIDEIOCs(test_mode, ioctype, url,tide_apikey):
	data ={}
	filename = './tide_'+ ioctype + '.json'
	
	if not test_mode:
		method='GET'
		auth = base64.encodebytes(('%s:%s' % (tide_apikey,' ')).encode()).decode().replace('\n', '').strip()
		
		ssl._create_default_https_context = ssl._create_unverified_context
		
		opener = urllib.request.build_opener()
		opener.addheaders = opener.addheaders = [('Authorization', 'Basic %s' % auth ), ('Content-Type','application/x-www-form-urlencoded') ,('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36')]
		urllib.request.install_opener(opener)
		urllib.request.urlretrieve(url, filename)

	file= open(filename, 'r')
	
	for line in file:
		try:
			r_json=json.loads(line)
		except:
			raise Exception('Unable to load into a json format')

		if r_json['type'] == 'HOST':
			data[r_json['host']] = ''
		elif r_json['type'] == 'IP':
			data[r_json['ip']] = ''
	
	logging.info('Download ok, {} TIDE IOCs: {}'.format(ioctype,len(data)))
	file.close()
	return data
	
#########################################################
	
def getFortiguardIOCs(test_mode, fortiguard_apikey):
	data ={}

	headers= {'Token': '{}'.format(fortiguard_apikey)}
	filename = './fortinet_all.csv'
	
	if not test_mode:
		url= 'https://premiumapi.fortinet.com/v1/cti/feed/csv?cc=all'
		response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
		
		url = response.json()[0]['data']
		response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
		
		open(filename, 'wb').write(gzip.decompress(response.content))

	file=open(filename, 'r')
	
	for line in file:
		line = line.strip()
		try:
			if is_fqdn(line) or ipaddress.ip_address(line):
				IOC = {}
				IOC['item']=line
				data[line] = IOC
		except:
			pass
		

	logging.info('Download ok, Fortinet IOCs: {}'.format(len(data)))
	file.close()
	return data

#########################################################			

def generate_new_IOC_list(TIDE_IOCs,Fortiguard_IOCs):
	data ={}
	diff = set(Fortiguard_IOCs).difference(set(TIDE_IOCs))
	for k in diff:
		data[k] = Fortiguard_IOCs[k]
	
	logging.info('IOC overlapping is {}%'.format(int(100-100*len(data)/len(Fortiguard_IOCs))))
	logging.info('IOCs in Fortiguard: {}'.format(len(Fortiguard_IOCs)))
	logging.info('IOCs in TIDE: {}'.format(len(TIDE_IOCs)))
	logging.info('IOCs in Fortiguard but not in TIDE: {}'.format(len(data)))
	
	return data

#########################################################	

def get_named_lists(named_list_prefix,headers):
	list_of_named_lists=[]
	response = requests.get('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, verify=True, timeout=(300,300))
	r_json = response.json()['results']
	for named_list in r_json:
		if re.match('^'+named_list_prefix+'\d+', named_list['name']):
			list_of_named_lists.append(named_list)
			
	return list_of_named_lists

#########################################################	

def update_to_csp(new_IOCs, csp_apikey):
		
	headers= {'Authorization': 'Token {}'.format(csp_apikey)}
	max_records_per_csp_list=10000
	named_list_prefix='Fortiguard_IOC_'
	existing_IOCs= {}
	IOCs_to_add = [{'description': 'do not remove', 'item': 'must_have_at_least_1_bad_domain.xyz'}]
	IOCs_to_remove = []

	#Get all named_lists ################################
	list_of_named_lists = get_named_lists(named_list_prefix,headers)
	
	#Get named lists content ############################
	for name_list in list_of_named_lists:
		response = requests.get('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}'.format(name_list['id']), headers=headers, verify=True, timeout=(300,300))
		for item in response.json()['results']['items_described']:
			item['named_list_id'] = name_list['id']
			existing_IOCs[item['item']] = item


	#Deduplicate to get the IOCs to add #################
	test= set(new_IOCs)
	test2 = set(existing_IOCs)
	diff = set(new_IOCs).difference(set(existing_IOCs))
	IOCs_to_add  = [new_IOCs[k] for k in diff]
	
			
	#Get the IOCs to remove #############################
	diff = set(existing_IOCs).difference(set(new_IOCs))	
	IOCs_to_remove  = [existing_IOCs[k] for k in diff]

	#Clean the lists#####################################
	for name_list in list_of_named_lists:
		filtered_IOCs_to_remove=[]
		for IOC_to_remove in IOCs_to_remove:
			if 'named_list_id' in IOC_to_remove and IOC_to_remove['named_list_id'] == name_list['id']:
				del IOC_to_remove['named_list_id']
				filtered_IOCs_to_remove.append(IOC_to_remove)
		if len(filtered_IOCs_to_remove) > 0:
			json_to_delete={}
			json_to_delete['items_described']=filtered_IOCs_to_remove
			logging.info("Cleaning {} entries in named_list {}, {}".format(len(filtered_IOCs_to_remove),name_list['name'],name_list['id']))
			response = requests.delete('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(name_list['id']), headers=headers, data=json.dumps(json_to_delete, indent=4, sort_keys=True), verify=True, timeout=(300,300))
			
	
	#Determining if additional lists are required #######
	named_lists_current_capacity = max_records_per_csp_list * len(list_of_named_lists)
	named_list_capacity_required = len(existing_IOCs) - len(IOCs_to_remove) + len (IOCs_to_add)
	number_of_named_list_to_create = max(0,math.ceil((named_list_capacity_required - named_lists_current_capacity) / max_records_per_csp_list))
		
	logging.info('named_lists_current_capacity = {}, named_list_capacity_required = {}, number_of_named_list_to_create = {}'.format(named_lists_current_capacity,named_list_capacity_required,number_of_named_list_to_create))

	
	#Create the List ####################################
	name_list_names=[0]
	for named_list in list_of_named_lists:
		name_list_names.append(int(re.search('\d+$', named_list['name']).group(0)))
	
	for i in range ( 1 , number_of_named_list_to_create+1):
		json_to_create = '{"name": "'+ named_list_prefix + str(i+max(name_list_names)) +'", "type": "custom_list", "confidence_level": "MEDIUM", "threat_level": "MEDIUM", "items_described": [ { "description": "do not remove", "item": "must_have_at_least_1_bad_domain.xyz" }]}'
		logging.info("Adding Named_list {}".format(named_list_prefix + str(i+max(name_list_names))))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, data=json_to_create, verify=True, timeout=(300,300))


	#Update available Named Lists #######################	
	list_of_named_lists = get_named_lists(named_list_prefix,headers)
	
	
	#Add to list ########################################
	logging.debug('{:<20}  {:<50}'.format('-- Description --','-- IOC --'))
	i=0
	for named_list in list_of_named_lists:
		IOCs_to_add_to_list = []
		j=0
		while int(j + int(named_list['item_count'])) < max_records_per_csp_list and i < len(IOCs_to_add):
			IOCs_to_add_to_list.append(IOCs_to_add[i])
			logging.debug('{:<20}  {:<50}'.format(IOCs_to_add[i].get('description',''),IOCs_to_add[i].get('item','')))
			i +=1
			j +=1
		json_to_add={}
		json_to_add['items_described'] = IOCs_to_add_to_list
		
		logging.info("Adding {} entries in named_list {}, {}".format(len(IOCs_to_add_to_list),named_list['name'],named_list['id']))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(named_list['id']), headers=headers, data=json.dumps(json_to_add, indent=4, sort_keys=True), verify=True, timeout=(300,300))
		try:
			response.raise_for_status()
		except requests.exceptions.HTTPError as e:
			return "Error: " + str(e)

	#########################################################			

hosts_url = 'https://api.activetrust.net/api/data/threats/state/host?data_format=ndjson'
ips_url   = 'https://api.activetrust.net/api/data/threats/state/IP?data_format=ndjson'

TIDE = {}
TIDE = getTIDEIOCs(use_already_downloaded_IOC_files, 'host', hosts_url, tide_apikey)
TIDE.update(getTIDEIOCs(use_already_downloaded_IOC_files, 'ip', ips_url, tide_apikey))

Fortiguard_IOCs = getFortiguardIOCs(use_already_downloaded_IOC_files, fortiguard_apikey)

new_IOCs = generate_new_IOC_list(TIDE, Fortiguard_IOCs)

update_to_csp(new_IOCs, csp_apikey)
