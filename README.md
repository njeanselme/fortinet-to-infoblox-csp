# fortinet-to-infoblox-csp
BloxOne Threat Defense integration with Fortiguard domain names and IPs brings an even wider threat intelligence coverage and protection.
Fortinet IOCs are enforced at DNS level globally on all the organization DNS even for roaming users who have not established their VPN.

This python scripts 
1) downloads all domain names and IP IOCs from Infoblox TIDE
2) downloads all IOCs from Fortiguard premium API
3) tests all domain names and IP IOCs from Fortinet to check if already present in TIDE and generates a list of new IOCs
4) downloads all Fortiguard_* named_lists from csp.infoblox.com 
5) removes entries from csp.infoblox.com that are not anymore in the list of new IOCs
6) creates new named_lists if capacity requires it
7) adds entries from the list of new IOCS to the named_lists

Prerequisistes:  
5GB+ disk for IOCs download  
1GB+ RAM 

Installation:  
Set the following api keys:  
tide_apikey = ''  
csp_apikey  = ''  
fortiguard_apikey= ''  

Outputs:  

2020-07-09 14:18:22,396 - root - INFO - Download ok, host TIDE IOCs: 4024664  
2020-07-09 14:20:04,396 - root - INFO - Download ok, ip TIDE IOCs: 234286  
2020-07-09 14:22:37,979 - root - INFO - Loading STIX package in memory OK  
2020-07-09 14:23:12,185 - root - INFO - Download ok, Fortinet IOCs: 41618  
2020-07-09 14:23:13,754 - root - INFO - IOC overlapping is 49%  
2020-07-09 14:23:13,755 - root - INFO - IOCs in Fortiguard: 41618  
2020-07-09 14:23:13,756 - root - INFO - IOCs in TIDE: 4258950  
2020-07-09 14:23:13,756 - root - INFO - IOCs in Fortiguard but not in TIDE: 20975  
2020-07-09 14:23:22,069 - root - INFO - Cleaning 1 entries in named_list Fortiguard_IOC_3, 656901  
2020-07-09 14:23:22,593 - root - INFO - named_lists_current_capacity = 60000, named_list_capacity_required = 20975, number_of_named_list_to_create = 0  
2020-07-09 14:23:25,292 - root - INFO - Adding 9999 entries in named_list Fortiguard_IOC_1, 656899  
2020-07-09 14:23:42,876 - root - INFO - Adding 9999 entries in named_list Fortiguard_IOC_2, 656900  
2020-07-09 14:24:00,414 - root - INFO - Adding 977 entries in named_list Fortiguard_IOC_3, 656901  
2020-07-09 14:24:02,041 - root - INFO - Adding 0 entries in named_list Fortiguard_IOC_4, 656910  
2020-07-09 14:24:02,546 - root - INFO - Adding 0 entries in named_list Fortiguard_IOC_5, 656914  
2020-07-09 14:24:03,172 - root - INFO - Adding 0 entries in named_list Fortiguard_IOC_6, 656915  
