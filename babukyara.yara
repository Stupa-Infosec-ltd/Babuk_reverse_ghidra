rule malware
{
    meta:
        description = "For babuk Ransomware"
        author = "Manoj Ghimire"
  	malware-family = “Ransom:Win/Babuk” 
        hash256 = "8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9"
	
    strings:
	
        $string1 = "BY BABUK LOCKER"
	$string2 = "http://babukq4e2p4wu4iq.onion"
	$string3 = "-lanfirst"
	$string4 = "-lansecond"
	$string5 = "-nolan"
	$gen_randomnumber = {55 8b ec 83 ec 08 68 c0 81 40 00 ff 15 5c 90 40 00 68 54 17 40 00 ff 15 38 90 40 00 89 45 fc 68 64 17 40 00 8b 45 fc 50 ff 15 34 90 40 00 89 45 f8 6a 58 68 d8 81 40 00 ff 55 f8 8b e5 5d c3 cc}
	$ecdh_generate_keys = {55 8b ec 83 ec 08 68 50 18 40 00 68 08 18 40 00 8b 45 08 83 c0 48 50 8b 4d 08 51 e8 10 07 00 00 83 c4 10 8b 55 0c 52 e8 94 02 00 00 83 c4 04 3d 1d 01 00 00 7d 06 33 c0 eb 5d eb 5b 68 98 18 40 00 e8 7a 02 00 00 83 c4 04 89 45 f8 8b 45 f8 83 e8 01 89 45 fc eb 09 8b 4d fc 83 c1 01 89 4d fc 81 7d fc 40 02 00 00 7d 12 8b 55 fc 52 8b 45 0c 50 e8 ba 00 00 00 83 c4 08 eb dc 8b 4d 0c 51 8b 55 08 83 c2 48 52 8b 45 08 50 e8 f1 09 00 00 83 c4 0c b8 01 00 00 00 8b e5 5d c3 cc cc cc cc cc}
	$public_key = {8d 85 f4 fd ff ff 50 68 88 22 40 00 ff 15 6c 90 40 00 68 98 22 40 00 8d 8d f4 fd ff ff 51 ff}
	$restore_file = {cc 21 40 00 8d 95 d4 fd ff ff 52 ff 15 40 90 40}
	$extension = {8d 94 4d d4 fd ff ff 52 ff}
    condition:
	uint16(0)== 0x5A4D and  all of ($string*) and $gen_randomnumber and $ecdh_generate_keys and $public_key and $restore_file and $extension
}


