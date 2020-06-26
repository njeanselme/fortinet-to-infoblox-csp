# fortinet-to-infoblox-csp
BloxOne Threat Defense integration with Fortiguard domain names and IPs brings an even wider threat intelligence coverage and protection.
Fortinet IOCs are enforced at DNS level globally on all the organization DNS even for roaming users who have not established their VPN.

This python scripts 
1) downloads all domain names and IP IOCs from Infoblox TIDE
2) downloads all IOCs from Fortiguard premium API
3) tests all domain names and IP IOCs from Fortinet to check if already present in TIDE add generates a list of new IOCs
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

2020-06-26 11:56:13,776 - root - INFO - Download ok, host TIDE IOCs: 3533421  
2020-06-26 11:56:16,418 - root - INFO - Download ok, ip TIDE IOCs: 133353  
2020-06-26 11:56:16,617 - root - INFO - Download ok, Fortinet IOCs: 48877  
2020-06-26 11:56:17,727 - root - INFO - IOC overlapping is" 42%  
2020-06-26 11:56:17,728 - root - INFO - IOCs in Fortiguard: 48877  
2020-06-26 11:56:17,730 - root - INFO - IOCs in TIDE: 3666774  
2020-06-26 11:56:17,731 - root - INFO - IOCs in Fortiguard but not in TIDE: 28026  
2020-06-26 12:23:06,922 - root - INFO - Adding Named_list Fortiguard_IOC_1  
2020-06-26 12:23:07,402 - root - INFO - Adding Named_list Fortiguard_IOC_2  
2020-06-26 12:23:08,240 - root - INFO - Adding Named_list Fortiguard_IOC_3  
2020-06-26 12:23:10,089 - root - INFO - Adding 9999 entries in named_list Fortiguard_IOC_1, 656899  
2020-06-26 12:23:17,987 - root - INFO - Adding 9999 entries in named_list Fortiguard_IOC_2, 656900  
2020-06-26 12:23:25,145 - root - INFO - Adding 7923 entries in named_list Fortiguard_IOC_3, 656901  
