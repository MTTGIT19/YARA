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
