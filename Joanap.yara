rule Joanap_malware {	
    meta:
        description = "Sample.exe, Joanap malware"
		md5 = "7FE80CEE04003FED91C02E3A372F4B01"
		author = "Matt"
		date = "2023-02-19"
	strings:
		$s1 = "OpenSCManagerA" nocase
		$s2 = "connection" nocase
		$s3 = "net share" nocase
		$s4 = "SystemRoot%" nocase
	condition:
		all of them
}

rule generic_bruteforcing {
	meta:
		description = "Evidence of brute-forcing"
		md5 = "7FE80CEE04003FED91C02E3A372F4B01"
		author = "Matt"
		date = "2023-02-19"
	strings:
		$s1 = "password" fullword nocase
		$s2 = "passw0rd" fullword nocase
		$s3 = "p@ssw0rd!" fullword nocase
		$s4 = "admin123" fullword nocase
	condition:
		all of them 
}
