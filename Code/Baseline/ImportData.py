import pandas as pd
import re
import MitreScraper
import json

Messages_mapping = {'ET DNS Query for .cc TLD [**] [Classification: Potentially Bad Traffic]': None,
 'ET DNS Query for .su TLD (Soviet Union) Often Malware Related [**] [Classification: Potentially Bad Traffic]': None,
 'ET DNS Query for .to TLD [**] [Classification: Potentially Bad Traffic]': None,
 'ET DNS Query to a *.pw domain - Likely Hostile [**] [Classification: Potentially Bad Traffic]': None,
 'ET DNS Query to a *.top domain - Likely Hostile [**] [Classification: Potentially Bad Traffic]': None,
 'ET DROP Spamhaus DROP Listed Traffic Inbound group 39 [**] [Classification: Misc Attack]': 'T1133',
 'ET HUNTING [TW] Likely Javascript-Obfuscator Usage Observed M1 [**] [Classification: Misc activity]': 'T1027',
 'ET INFO DropBox User Content Domain (dl .dropboxusercontent .com in TLS SNI) [**] [Classification: Misc activity]': 'T1567',
 'ET INFO External IP Address Lookup Domain (ipify .org) in TLS SNI [**] [Classification: Misc activity]': 'T1614',
 'ET INFO External IP Lookup Domain (freegeiop .net in DNS lookup) [**] [Classification: Device Retrieving External IP Address Detected]': 'T1614',
 'ET INFO External IP Lookup Domain (ipify .org) in DNS Lookup [**] [Classification: Misc activity]': 'T1614',
 'ET INFO HTTP Request to a *.asia domain [**] [Classification: Potentially Bad Traffic]': None,
 'ET INFO HTTP Request to a *.top domain [**] [Classification: Potentially Bad Traffic]': None,
 'ET INFO HTTP Request to a *.tw domain [**] [Classification: Potentially Bad Traffic]': None,
 'ET INFO JAVA - ClassID [**] [Classification: Misc activity]': None,
 'ET INFO Observed DNS Query to .biz TLD [**] [Classification: Potentially Bad Traffic]': None,
 'ET INFO Observed Discord Domain (discordapp .com in TLS SNI) [**] [Classification: Misc activity]': None,
 'ET INFO Observed Discord Domain in DNS Lookup (discordapp .com) [**] [Classification: Misc activity]': None,
 'ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port) [**] [Classification: Misc activity]': None,
 'ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard Low Port) [**] [Classification: Misc activity]': None,
 'ET INFO Session Traversal Utilities for NAT (STUN Binding Request) [**] [Classification: Misc activity]': None,
 'ET INFO Session Traversal Utilities for NAT (STUN Binding Response) [**] [Classification: Misc activity]': None,
 'ET INFO TLS Handshake Failure [**] [Classification: Potentially Bad Traffic]': None,
 'ET INFO Windows OS Submitting USB Metadata to Microsoft [**] [Classification: Misc activity]': None,
 'ET JA3 Hash - [Abuse.ch] Possible Adware [**] [Classification: Unknown Traffic]': 'T1082',
 'ET MALWARE Win32/Suspected Reverse Shell Connection [**] [Classification: A Network Trojan was detected]': 'T1659',
 'ET MALWARE Windows Microsoft Windows DOS prompt command Error not recognized [**] [Classification: A Network Trojan was detected]': 'T1059.003',
 'ET MALWARE Windows dir Microsoft Windows DOS prompt command exit OUTBOUND [**] [Classification: A Network Trojan was detected]': 'T1059.003',
 'ET PHISHING Possible Phishing Redirect Dec 13 2016 [**] [Classification: Possible Social Engineering Attempted]': 'T1566',
 'ET POLICY DNS Query For XXX Adult Site Top Level Domain [**] [Classification: Potential Corporate Privacy Violation]': None,
 'ET POLICY Dropbox.com Offsite File Backup in Use [**] [Classification: Potential Corporate Privacy Violation]': 'T1567',
 'ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management [**] [Classification: Not Suspicious Traffic]': None,
 'ET POLICY HTTP HEAD invalid method case outbound [**] [Classification: Potentially Bad Traffic]': None,
 'ET POLICY HTTP POST invalid method case outbound [**] [Classification: Potentially Bad Traffic]': None,
 'ET POLICY PE EXE or DLL Windows file download HTTP [**] [Classification: Potential Corporate Privacy Violation]': 'T1105',
 'ET POLICY Possible IP Check api.ipify.org [**] [Classification: Potential Corporate Privacy Violation]': 'T1614',
 'ET POLICY Vulnerable Java Version 1.8.x Detected [**] [Classification: Potentially Bad Traffic]': 'T1203',
 'ET POLICY curl User-Agent Outbound [**] [Classification: Attempted Information Leak]': 'T1071.002',
 'ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection [**] [Classification: Misc activity]': 'T1595.001',
 'ET SCAN Possible Nmap User-Agent Observed [**] [Classification: Web Application Attack]': 'T1595.001',
 'ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent [**] [Classification: Misc activity]': None,
 'GPL EXPLOIT Microsoft cmd.exe banner [**] [Classification: Successful Administrator Privilege Gain]': 'T1068',
 'SURICATA Applayer Detect protocol only one direction [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA Applayer Mismatch protocol both directions [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA Applayer Wrong direction first Data [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA FRAG IPv4 Fragmentation overlap [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Host header ambiguous [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Host header invalid [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Request abnormal Content-Encoding header [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Request line incomplete [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Request line with leading whitespace [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Request unrecognized authorization method [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Response abnormal chunked for transfer-encoding [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Response invalid protocol [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Response invalid status [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP Unexpected Request body [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP duplicate content length field in response [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP gzip decompression failed [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP invalid response chunk len [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP invalid response field folding [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP request field missing colon [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP request header invalid [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP response field missing colon [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP response header invalid [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA HTTP unable to match response to request [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA ICMPv4 unknown code [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA Kerberos 5 weak encryption parameters [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA SMB file overlap [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA SMB malformed request dialects [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM 3way handshake SYN resend different seq on SYN recv [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM 3way handshake right seq wrong ack evasion [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM 3way handshake wrong seq wrong ack [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM CLOSEWAIT FIN out of window [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM ESTABLISHED SYNACK resend [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM ESTABLISHED invalid ack [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM ESTABLISHED packet out of window [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM FIN invalid ack [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM FIN out of window [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM FIN1 FIN with wrong seq [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM Packet with invalid ack [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM Packet with invalid timestamp [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM SHUTDOWN RST invalid ack [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM TIMEWAIT ACK with wrong seq [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM bad window update [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM excessive retransmissions [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA STREAM reassembly overlap with different data [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA TLS invalid record type [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA TLS invalid record/traffic [**] [Classification: Generic Protocol Command Decode]': None,
 'SURICATA UDPv6 invalid checksum [**] [Classification: Generic Protocol Command Decode]': None,
 'ET POLICY Python-urllib/ Suspicious User Agent Attempted Information Leak': 'T1041',
 'ET SCAN Possible Nmap User-Agent Observed Web Application Attack': 'T1595.002',
 'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) Web Application Attack': 'T1595.002',
 'ET SCAN NMAP SIP Version Detect OPTIONS Scan Attempted Information Leak': 'T1595.002',
 'ET SCAN Potential SSH Scan Attempted Information Leak': 'T1595.001',
 'ET SCAN Suspicious inbound to PostgreSQL port 5432 Potentially Bad Traffic': 'T1595',
 'ET SCAN Suspicious inbound to MSSQL port 1433 Potentially Bad Traffic': 'T1595',
 'ET SCAN Suspicious inbound to mSQL port 4333 Potentially Bad Traffic': 'T1595',
 'ET SCAN Suspicious inbound to Oracle SQL port 1521 Potentially Bad Traffic': 'T1595',
 'ET SCAN Suspicious inbound to mySQL port 3306 Potentially Bad Traffic': 'T1595',
 'ET SCAN Potential VNC Scan 5800-5820 Attempted Information Leak': 'T1595',
 'ET SCAN Potential VNC Scan 5900-5920 Attempted Information Leak': 'T1595',
 'ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management Not Suspicious Traffic': None,
 'ET SCAN NMAP SIP Version Detection Script Activity Attempted Information Leak': 'T1595.002',
 'ET POLICY Http Client Body contains passwd= in cleartext Potential Corporate Privacy Violation': 'T1003.008',
 'GPL WEB_SERVER 403 Forbidden Attempted Information Leak': None,
 'ETPRO WEB_SPECIFIC_APPS PHPMoAdmin RCE Attempt Web Application Attack': None,
 'ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY. A Network Trojan was detected': 'T1190',
 'GPL EXPLOIT .cnf access access to a potentially vulnerable web application': 'T1190',
 'GPL WEB_SERVER author.exe access access to a potentially vulnerable web application': 'T1190',
 'ET WEB_SPECIFIC_APPS Possible JBoss JMX Console Beanshell Deployer WAR Upload and Deployment Exploit Attempt Web Application Attack': 'T1059',
 'ET WEB_SERVER ColdFusion componentutils access Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Horde type Parameter Local File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Request to Wordpress W3TC Plug-in dbcache Directory A Network Trojan was detected': 'T1190',
 'ET WEB_SERVER /etc/shadow Detected in URI Attempted Information Leak': 'T1003.008',
 'ET WEB_SPECIFIC_APPS PHP-CGI query string parameter vulnerability Web Application Attack': 'T1003',
 'ET WEB_SERVER WEB-PHP phpinfo access Information Leak': 'T1190',
 'ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt Web Application Attack': 'T1659',
 'ET WEB_SERVER PHP SERVER SuperGlobal in URI Potentially Bad Traffic': 'T1190',
 'ET WEB_SPECIFIC_APPS Ve-EDIT edit_htmlarea.php highlighter Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=) Web Application Attack': 'T1059',
 'ET WEB_SPECIFIC_APPS SAPID get_infochannel.inc.php Remote File inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SERVER PHP SESSION SuperGlobal in URI Potentially Bad Traffic': 'T1190',
 'ET WEB_SPECIFIC_APPS PHP Aardvark Topsites PHP CONFIG PATH Remote File Include Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS BASE base_stat_common.php remote file include Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS phpSkelSite theme parameter remote file inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS TECHNOTE shop_this_skin_path Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS phPortal gunaysoft.php sayfaid Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS phPortal gunaysoft.php icerikyolu Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS ProjectButler RFI attempt  Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS MODx CMS snippet.reflect.php reflect_base Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS FormMailer formmailer.admin.inc.php BASE_DIR Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS MAXcms fm_includes_special Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS SERWeb main_prepend.php functionsdir Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Sisplet CMS komentar.php site_path Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS SERWeb load_lang.php configdir Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS OpenX phpAdsNew phpAds_geoPlugin Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Possible eFront database.php Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS p-Table for WordPress wptable-tinymce.php ABSPATH Parameter RFI Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS AjaxPortal di.php pathtoserverdata Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SERVER PHP REQUEST SuperGlobal in URI Potentially Bad Traffic': None,
 'ET WEB_SPECIFIC_APPS PointComma pctemplate.php pcConfig Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS ProdLer prodler.class.php sPath Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS KingCMS menu.php CONFIG Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS YapBB class_yapbbcooker.php cfgIncludeDirectory Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS PHP-Paid4Mail RFI attempt  Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS OBOphiX fonctions_racine.php chemin_lib parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Enthusiast path parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Achievo debugger.php config_atkroot parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS PHPOF DB_AdoDB.Class.PHP PHPOF_INCLUDE_PATH parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Mambo Component com_smf smf.php Remote File Inclusion Attempt Web Application Attack': 'T1190',
 "ET WEB_SPECIFIC_APPS Possible Mambo/Joomla! com_koesubmit Component 'koesubmit.php' Remote File Inclusion Attempt Web Application Attack": 'T1190',
 'ET WEB_SPECIFIC_APPS Joomla AjaxChat Component ajcuser.php GLOBALS Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SERVER PHP ENV SuperGlobal in URI Potentially Bad Traffic': None,
 'ET WEB_SPECIFIC_APPS phptraverse mp3_id.php GLOBALS Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS PHP phpMyAgenda rootagenda Remote File Include Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Joomla swMenuPro ImageManager.php Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Joomla Simple RSS Reader admin.rssreader.php mosConfig_live_site Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Joomla Onguma Time Sheet Component onguma.class.php mosConfig_absolute_path Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Joomla Dada Mail Manager Component config.dadamail.php GLOBALS Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Golem Gaming Portal root_path Parameter Remote File inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS Possible OpenSiteAdmin pageHeader.php Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS PHP Classifieds class.phpmailer.php lang_path Parameter Remote File Inclusion Attempt Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS DesktopOnNet frontpage.php app_path Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'ET WEB_SPECIFIC_APPS DesktopOnNet don3_requiem.php app_path Parameter Remote File Inclusion Web Application Attack': 'T1190',
 'GPL EXPLOIT ISAPI .idq access access to a potentially vulnerable web application': 'T1190',
 'GPL EXPLOIT iissamples access Web Application Attack': 'T1190',
 'GPL EXPLOIT ISAPI .idq attempt Web Application Attack': 'T1190',
 'GPL WEB_SERVER global.asa access access to a potentially vulnerable web application': None,
 'GPL EXPLOIT /msadc/samples/ access Web Application Attack': 'T1190',
 'ET WEB_SERVER /system32/ in Uri - Possible Protected Directory Access Attempt Attempted Information Leak': 'T1190',
 'ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt Attempted Information Leak': 'T1190',
 'GPL WEB_SERVER viewcode access Web Application Attack': 'T1190',
 'GPL EXPLOIT unicode directory traversal attempt Web Application Attack': 'T1190',
 'GPL EXPLOIT fpcount access access to a potentially vulnerable web application': 'T1190',
 'ET WEB_SERVER ColdFusion administrator access Web Application Attack': 'T1190',
 'GPL WEB_SERVER service.pwd access to a potentially vulnerable web application': 'T1190',
 'GPL WEB_SERVER authors.pwd access access to a potentially vulnerable web application': 'T1190',
 'GPL EXPLOIT administrators.pwd access access to a potentially vulnerable web application': 'T1190',
 'ET WEB_SERVER SELECT USER SQL Injection Attempt in URI Web Application Attack': 'T1003',
 'ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM Web Application Attack': 'T1190',
 'GPL WEB_SERVER Oracle Java Process Manager access access to a potentially vulnerable web application': None,
 'GPL WEB_SERVER .htaccess access Attempted Information Leak': 'T1213',
 'GPL WEB_SERVER .htpasswd access Web Application Attack': 'T1213',
 'GPL WEB_SERVER globals.pl access access to a potentially vulnerable web application': 'T1190',
 'GPL EXPLOIT .htr access access to a potentially vulnerable web application': 'T1190',
 'GPL EXPLOIT iisadmpwd attempt Web Application Attack': 'T1213',
 'GPL EXPLOIT /iisadmpwd/aexp2.htr access access to a potentially vulnerable web application': 'T1190',
 'ET WEB_SPECIFIC_APPS WEB-PHP RCE PHPBB 2004-1315 Web Application Attack': 'T1190',
 'ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo) Attempted Information Leak': None,
 'ET WEB_SERVER PHP Easteregg Information-Disclosure (php-logo) Attempted Information Leak': None,
 'ET WEB_SERVER PHP Easteregg Information-Disclosure (funny-logo) Attempted Information Leak': None,
 'ET WEB_SERVER PHP Easteregg Information-Disclosure (phpinfo) Attempted Information Leak': None,
 'GPL EXPLOIT ISAPI .ida access access to a potentially vulnerable web application': None,
 'GPL WEB_SERVER writeto.cnf access access to a potentially vulnerable web application': None,
 'GPL WEB_SERVER services.cnf access access to a potentially vulnerable web application': None,
 'GPL WEB_SERVER service.cnf access access to a potentially vulnerable web application': None,
 'ETPRO WEB_SPECIFIC_APPS ipTIME firmware < 9.58 RCE Web Application Attack': None,
 'GPL WEB_SERVER Tomcat server snoop access Attempted Information Leak': None,
 'GPL WEB_SERVER printenv access access to a potentially vulnerable web application': None,
 'ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt Web Application Attack': 'T1213',
 'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT Web Application Attack': 'T1190',
 'GPL WEB_SERVER iisadmin access Web Application Attack': None,
 'GPL EXPLOIT CodeRed v2 root.exe access Web Application Attack': 'T1190',
 'GPL WEB_SERVER /~root access Attempted Information Leak': 'T1190',
 'ET WEB_SERVER Possible CVE-2014-6271 Attempt Attempted Administrator Privilege Gain': 'T1210',
 'ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers Attempted Administrator Privilege Gain': 'T1210',
 'ET CURRENT_EVENTS QNAP Shellshock CVE-2014-6271 Attempted Administrator Privilege Gain': 'T1210',
 'ET POLICY Proxy TRACE Request - inbound Potentially Bad Traffic': None,
 'ET SCAN Nikto Web App Scan in Progress Web Application Attack': 'T1595',
 'ET WEB_SERVER Possible Cherokee Web Server GET AUX Request Denial Of Service Attempt Attempted Denial of Service': 'T1499.003',
 'GPL ICMP_INFO PING *NIX Misc activity': None,
 'ET POLICY IP Check Domain (icanhazip. com in HTTP Host) Attempted Information Leak': None,
 'ET POLICY curl User-Agent Outbound Attempted Information Leak': None,
 'ET SCAN Potential SSH Scan OUTBOUND Attempted Information Leak': 'T1595',
 'GPL DNS named version attempt Attempted Information Leak': None,
 'GPL SNMP public access udp Attempted Information Leak': None,
 'ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION Web Application Attack': None,
 'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE) Web Application Attack': 'T1595',
 'ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted Potential Corporate Privacy Violation': None,
 'ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted Potential Corporate Privacy Violation': None,
 'ETPRO ATTACK_RESPONSE MongoDB Version Request Successful Administrator Privilege Gain': 'T1003',
 'ETPRO ATTACK_RESPONSE MongoDB Database Enumeration Request Successful Administrator Privilege Gain': 'T1003',
 'ET WEB_SERVER /bin/bash In URI Possible Shell Command Execution Attempt Within Web Exploit Web Application Attack': 'T1190',
 'ET ATTACK_RESPONSE Output of id command from HTTP server Potentially Bad Traffic': 'T1059',
 'ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt Web Application Attack': 'T1059',
 'ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 4 (Inbound to Common SSL Port) Potentially Bad Traffic': None,
 'ET CURRENT_EVENTS Malformed HeartBeat Request Potentially Bad Traffic': None,
 'ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack Misc activity': 'T1110',
 'ET SCAN Rapid POP3S Connections - Possible Brute Force Attack Misc activity': 'T1110',
 'ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access Web Application Attack': 'T1190',
 'ET SCAN Sqlmap SQL Injection Scan Attempted Information Leak': 'T1595',
 'ETPRO WEB_SERVER SQLMap Scan Tool User Agent Web Application Attack': 'T1595',
 'ET SCAN Rapid POP3 Connections - Possible Brute Force Attack Misc activity': 'T1110',
 'GPL WEB_SERVER DELETE attempt access to a potentially vulnerable web application': 'T1190',
 'ET POLICY POSSIBLE Web Crawl using Wget Attempted Information Leak': 'T1595',
 'ET SCAN NMAP OS Detection Probe Attempted Information Leak': 'T1595.001',
 'ET SCAN Rapid IMAP Connections - Possible Brute Force Attack Misc activity': 'T1110',
 'ET WEB_SERVER /bin/bash In URI, Possible Shell Command Execution Attempt Within Web Exploit Web Application Attack': 'T1059',
 'ET USER_AGENTS Go HTTP Client User-Agent Misc activity': None,
 'GPL SMTP vrfy root Attempted Information Leak': None,
 'GPL SMTP expn root Attempted Information Leak': None,
 'ETPRO SCAN IPMI Get Authentication Request (null seq number - null sessionID) A Network Trojan was detected': 'T1078',
 'GPL RPC xdmcp info query Attempted Information Leak': None,
 'ET INFO Executable Download from dotted-quad Host A Network Trojan was detected': 'T1189',
 'ET POLICY POSSIBLE Web Crawl using Curl Attempted Information Leak': None,
 'ET POLICY Outbound MSSQL Connection to Non-Standard Port - Likely Malware Potentially Bad Traffic': None,
 'ETPRO WEB_SERVER Possible Information Leak Vuln CVE-2015-1648 Web Application Attack': 'T1213',
 'ETPRO WEB_SERVER JexBoss Common URI struct Observed 2 (INBOUND) A Network Trojan was detected': None,
 'ET WEB_SERVER Suspicious Chmod Usage in URI Attempted Administrator Privilege Gain': None,
 'ET POLICY Executable and linking format (ELF) file download Potential Corporate Privacy Violation': 'T1204.002',
 'ET SCAN Grendel-Scan Web Application Security Scan Detected Attempted Information Leak': 'T1595',
 'ET TROJAN Backdoor family PCRat/Gh0st CnC traffic (OUTBOUND) 106 A Network Trojan was detected': 'T1041'}

Mitre_mapping = {
    None: 0,
    'Reconnaissance': 1,
    'Discovery': 1,
    'Initial Access': 2,
    'Credential Access': 2,
    'Execution': 3,
    'Persistence': 3,
    'Privilege Escalation': 3,
    'Lateral Movement': 3,
    'Defense Evasion': 3,
    'Command and Control': 4,
    'Collection': 4,
    'Exfiltration': 5,
    'Impact': 5,
}

storeTactics = {}

# transform standard SURICATA log file into a file readable by the deepcase library
def main(filepath: str = 'Dev/Data/alerts.log'):
    with open(filepath, 'r') as file:
        data = file.readlines()
        file.close()

    # Extracting the relevant parts and creating a list of lists
    formatted_data = []
    for row in data:
        try:
            split1 = re.split(r'\[\*\*\] \[[0-9]\:[0-9]+\:[0-9]+\]', row)
            split2 = re.split(r'\[Priority: [0-9]\]', split1[1])
            split3 = split2[1].split()

            date_time = split1[0].strip()
            message = split2[0].strip()
            protocol = split3[0].strip()
            source = split3[1].strip().split(':')[0]
            source_port = split3[1].strip().split(':')[1]
            dest = split3[3].strip().split(':')[0]
            dest_port = split3[3].strip().split(':')[1]

            technique = Messages_mapping[message]
            if technique != None:
                if technique in storeTactics:
                    tactics = storeTactics[technique]
                else:
                    storeTactics[technique] = MitreScraper.getTactic(technique)
                    tactics = storeTactics[technique]
                phase = Mitre_mapping[tactics[0]]
            else:
                phase = 0

            formatted_data.append([date_time, message, protocol.strip('{}'), source, source_port, dest, dest_port, phase])
        except Exception as e:
            print("Error in row: \n", row)
            print("\nError: ", e)
            break

    # Creating DataFrame
    df = pd.DataFrame(formatted_data, columns=['Date_Time', 'Message', 'Protocol', 'Source', 'Source Port', 'Destination', 'Destination Port', 'Phase'])

    return df


def importJson(filepath: str = 'Dev/Data/alerts.json'):
    print("\tImporting data from: ", filepath)
    df = pd.read_json(filepath)
    # Apply the function to each row

    print("\tParsing JSON...")
    # Apply pd.json_normalize directly on the entire column
    result_df = pd.json_normalize(df["_raw"].apply(json.loads))

    newColumnNames = {
        'timestamp': 'Date_Time',
        'proto': 'Protocol',
        'src_ip': 'Source',
        'src_port': 'Source Port',
        'dest_ip': 'Destination',
        'dest_port': 'Destination Port'
    }

    print("\tRenaming columns...")
    renamed_df = result_df.rename(columns=newColumnNames, inplace=False)
    result = renamed_df[['Date_Time', 'Protocol', 'Source', 'Source Port', 'Destination', 'Destination Port']].copy()
    # Concatenate alert.signature and alert.category columns
    concatenated_column = renamed_df['alert.signature'] + ' ' + renamed_df['alert.category']

    # Add the concatenated column to the result dataframe
    result.loc[:, 'Message'] = concatenated_column
    tacticList = []
    namesList = []
    techniquesList = []
    
    print("\tMapping messages to tactics and phases...")
    for _, row in result.iterrows():
        technique = Messages_mapping[row['Message']]
        if technique != None:
            if technique in storeTactics:
                tactics, title = storeTactics[technique]
            else:
                tactics, title = MitreScraper.getTactic(technique)
                storeTactics[technique] = tactics, title
        else:
            technique = 'None'
            title = 'None'

        tacticList.append(tactics)
        namesList.append(title)
        techniquesList.append(technique)

    result.loc[:, 'Technique'] = techniquesList
    result.loc[:, 'Technique Name'] = namesList
    result.loc[:, 'Tactics'] = tacticList

    # make date_time a datetime object
    result.loc[:, 'Date_Time'] = (pd.to_datetime(result['Date_Time']) - pd.to_datetime("01/01/1970-00:00:00.000000+00:00")) // pd.Timedelta('1ns')
    # Now sort the dataframe by date_time
    result.sort_values(by='Date_Time', inplace=True)
    # Reset the index
    result.reset_index(drop=True, inplace=True)

    return result


def FilterResults(df, timeframe = 1):
    # for all alerts, if they are alone within timeframe, remove them
    # if there are duplicate alerts within timeframe (based on source, destination, and message), remove all but the first

    return df

if __name__ == '__main__':
    importJson('Dev/Data/suricata_alert.json')
