rule Freeload_bot_malware {
	meta:
		description = "Bot.exe, Freeload malware"
		md5 = "361C983B94B3E07A3B509F0B9B34CAD7"
		author = "Matt"
		date = "2023-02-19"
	strings:
		$s1 = "digi-serv.be"
		$s2 = "prosium.php"
		$s3 = "yandex_service"
		$s4 = "WININET.dll" fullword ascii
		$s5 = "ADVAPI32.dll" fullword ascii
		$s6 = "KERNEL32.dll" fullword ascii
		$s7 = "WS2_32" fullword ascii
	condition:
		all of them 
}

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

