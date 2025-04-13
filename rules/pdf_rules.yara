rule malicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator\(yen vaw\)/
		$reg1 = /Title\(who cis\)/
		$reg2 = /Author\(ser pes\)/
	condition:
		$magic at 0 and all of ($reg*)
}

rule suspicious_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic at 0 and not $ver
}

rule suspicious_creation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic at 0 and $header and 1 of ($create*)
}

rule suspicious_title : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic at 0 and $header and 1 of ($title*)
}