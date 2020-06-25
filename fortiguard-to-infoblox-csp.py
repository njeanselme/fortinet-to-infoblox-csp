from stix.core import STIXPackage 
import requests
import base64
import json
import re
import math
import gzip


#########################################################			

tide_apikey = ''
csp_apikey  = ''
fortiguard_apikey= '' #not used yet

#########################################################

def getTIDEIOCs(url,tide_apikey):
	data ={}
	method='GET'
	auth = base64.encodebytes(('%s:%s' % (tide_apikey,' ')).encode()).decode().replace('\n', '').strip()
	headers = {
		'Authorization':'Basic %s' % auth,
		'Content-Type':'application/x-www-form-urlencoded',
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
		'Cache-Control': 'no-cache'
	}
	response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
	
	if response.encoding is None:
		response.encoding = 'utf-8'
		for line in response.iter_lines(decode_unicode=True):
			if line:
				try:
					r_json=json.loads(line)
				except:
					raise Exception('Unable to load into a json format')
	
				if r_json['type'] == 'HOST':
					data[r_json['host']] = ''
				elif r_json['type'] == 'IP':
					data[r_json['ip']] = ''
	return data
	
#########################################################
	
def getFortiguardIOCs(file,fortiguard_apikey):
	data ={}
	
	'''
	headers= {'Authorization': 'Token:{}'.format(fortiguard_apikey)}
	url= 'https://premiumapi.fortinet.com/v1/cti/feed/stix?cc=us'
	response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
	url = response.json()[0]['data']
	response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
	
	with gzip.open('/home/joe/file.txt.gz', 'rb') as file:
	    file_content = file.read()
	'''
	
	stix_package = STIXPackage.from_xml(file)

	ttps={}
	json_ttps = json.loads(stix_package.ttps.to_json())
	if 'ttps' in json_ttps:
		json_ttps=json_ttps['ttps']
		for json_ttp in json_ttps:
			if 'id' in json_ttp and 'title' in json_ttp:
				ttps[json_ttp['id']]=json_ttp['title']

	indicators = json.loads(stix_package.indicators.to_json())
	for indicator in indicators:
		IOC = {}
		try:
			r_json = indicator['observable']['object']['properties']		
			if 'type' in r_json and 'value' in r_json and r_json['type'] == 'Domain Name':
				IOC['item'] = r_json['value']
			elif 'ip_address' in r_json and 'address_value' in r_json['ip_address'] and 'value' in r_json['ip_address']['address_value']:
				IOC['item'] = r_json['ip_address']['address_value']['value']
				
			if 'indicated_ttps' in indicator and len(indicator['indicated_ttps'])>0 and 'ttp' in indicator['indicated_ttps'][0] and 'idref' in indicator['indicated_ttps'][0]['ttp']:
				ttp_id = indicator['indicated_ttps'][0]['ttp']['idref']
				if ttp_id in ttps:
					IOC['description'] = ttps[ttp_id]
			
			if 'item' in IOC:
				data[IOC['item']]=IOC
		except:
			pass

	return data

#########################################################			

def generate_new_IOC_list(TIDE_IOCs,Fortiguard_IOCs):
	data ={}
	diff = set(Fortiguard_IOCs).difference(set(TIDE_IOCs))	
	for k in diff:
		data[k] = Fortiguard_IOCs[k]
	
	print('IOC overlapping is {}%'.format(100-100*len(data)/len(Fortiguard_IOCs)))
	
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
			print("Cleaning {} entries in named_list {}, {}".format(len(filtered_IOCs_to_remove),name_list['name'],name_list['id']))
			response = requests.delete('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(name_list['id']), headers=headers, data=json.dumps(json_to_delete, indent=4, sort_keys=True), verify=True, timeout=(300,300))
			
	
	#Determining if additional lists are required #######
	named_lists_current_capacity = max_records_per_csp_list * len(list_of_named_lists)
	named_list_capacity_required = len(existing_IOCs) - len(IOCs_to_remove) + len (IOCs_to_add)
	number_of_named_list_to_create = max(0,math.ceil((named_list_capacity_required - named_lists_current_capacity) / max_records_per_csp_list))
		
	print('named_lists_current_capacity = {}, named_list_capacity_required = {}, number_of_named_list_to_create = {}'.format(named_lists_current_capacity,named_list_capacity_required,number_of_named_list_to_create))
	
	
	#Create the List ####################################
	name_list_names=[0]
	for named_list in list_of_named_lists:
		name_list_names.append(int(re.search('\d+$', named_list['name']).group(0)))
	
	for i in range ( 1 , number_of_named_list_to_create+1):
		json_to_create = '{"name": "'+ named_list_prefix + str(i+max(name_list_names)) +'", "type": "custom_list", "confidence_level": "MEDIUM", "threat_level": "MEDIUM", "items_described": [ { "description": "do not remove", "item": "must_have_at_least_1_bad_domain.xyz" }]}'
		print("Adding Named_list {}".format(named_list_prefix + str(i+max(name_list_names))))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, data=json_to_create, verify=True, timeout=(300,300))


	#Update available Named Lists #######################	
	list_of_named_lists = get_named_lists(named_list_prefix,headers)
	
	#Add to list ########################################
	i=0
	for named_list in list_of_named_lists:
		IOCs_to_add_to_list = []
		j=0
		while int(j + int(named_list['item_count'])) < max_records_per_csp_list and i < len(IOCs_to_add):
			IOCs_to_add_to_list.append(IOCs_to_add[i])
			i +=1
			j +=1
		json_to_add={}
		json_to_add['items_described'] = IOCs_to_add_to_list
		print("Adding {} entries in named_list {}, {}".format(len(IOCs_to_add_to_list),named_list['name'],named_list['id']))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(named_list['id']), headers=headers, data=json.dumps(json_to_add, indent=4, sort_keys=True), verify=True, timeout=(300,300))

	
	#########################################################			


hosts_url = 'https://api.activetrust.net/api/data/threats/state/host?data_format=ndjson'
ips_url   = 'https://api.activetrust.net/api/data/threats/state/IP?data_format=ndjson'

TIDE = getTIDEIOCs(hosts_url, tide_apikey)
TIDE.update(getTIDEIOCs(  ips_url, tide_apikey))

Fortiguard_IOCs = getFortiguardIOCs('sample.stix',fortiguard_apikey)
new_IOCs = generate_new_IOC_list(TIDE, Fortiguard_IOCs)

update_to_csp(new_IOCs, csp_apikey)
