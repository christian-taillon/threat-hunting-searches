## Log4j Searches compliment a full Threat Hunt Guide provided at [christian-taillon/log4shell-hunting](https://github.com/christian-taillon/log4shell-hunting).

## Generating
Log4j Network Extraction:
```
 ... search
  | rex field=foo ":(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})\/(?<threat_content>(?:[[:alnum:]]|\.){1,})))"
  | fields - foo _time
  | table elastic_source threat threat_host threat_port threat_content
  | outputlookup log4j-net-threats.csv
```


<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk_net_extract.png" width="700px"></h1>

Log4j Base64 Extraction:
```
 ... search
  | rex field=foo ":(?:\/){1,2}(?<threat>(?<threat_host>(?:[[:alnum:]]|\-|\.){1,})[\/|:](?:(?<threat_port>[0-9]{2,6})\/(?<threat_content>(?:[[:alnum:]]|\.){1,})))"
  | fields - foo _time
  | outputlookup log4j-base64-threats.csv
```

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk_base64_extract.png" width="700px"></h1>



## Matching
*Endpoint*

```
index=homelab sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 CommandLine=*
    [| inputlookup log4j-base64-threats.csv]
| table _time CommandLine host
```

*Network IP Addresses*
```
| tstats summariesonly=t count from datamodel=Network_Traffic where * by All_Traffic.dest All_Traffic.src All_Traffic.dest_port  All_Traffic.action All_Traffic.vendor_product
| search
    [| inputlookup log4j-net-threats.csv
    | rename threat_host as All_Traffic.dest
    | fields All_Traffic.dest ]
| sort - count
| eval threat_host = 'All_Traffic.dest'
| lookup log4j-net-threats.csv threat_host as threat_host
```

*Network Hostnames*
```
| tstats summariesonly=t count from datamodel=Web by Web.dest Web.src Web.dest_port Web.action Web.vendor_product Web.url
| search
    [| inputlookup log4j-net-threats.csv
    | rename threat_host as Web.url
    | fields Web.url ]
| sort - count
| eval threat_host = 'Web.url'
| lookup log4j-net-threats.csv  threat_host as threat_host
```

<h1><img src="https://github.com/christian-taillon/log4shell-hunting/blob/main/images/splunk-net-match.png" width="700px"></h1>
