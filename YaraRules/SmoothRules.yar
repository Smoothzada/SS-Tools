import "pe"

rule SRule1 {
    strings:
        $a = /Exodus\.codes/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule2 {
    strings:
        $a = /slinky\.gg/i ascii wide nocase
    condition:
        pe.is_pe and $a
}

rule SRule3 {
    strings:
        $a = /slinkyhook\.dll/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule4 {
    strings:
        $a = /slinky_library\.dll/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule5 {
    strings:
        $a = /\[!\] Failed to find Vape jar/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule6 {
    strings:
        $a = /Vape Launcher/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule7 {
    strings:
        $a = /vape\.gg/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule8 {
    strings:
        $a = /C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3\.pdb/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule9 {
    meta:
        author = "Smooth"
        description = "Detecta discord.gg/advantages"
    strings:
        $a = /discord\.gg\/advantages/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule10 {
    meta:
        author = "Smooth"
        description = "Detecta String cleaner"
    strings:
        $a = /String cleaner/i ascii wide
    condition:
        pe.is_pe and $a
}

rule SRule11 {
    meta:
        author = "Smooth"
        description = "Detecta string: Open Minecraft, then try again."
    strings:
        $k = /Open Minecraft, then try again\./i ascii wide
    condition:
        pe.is_pe and $k
}

rule SRule12 {
    meta:
        author = "Smooth"
        description = "Detecta string: The clicker code was done by Nightbot. I skidded it :)"
    strings:
        $l = /The clicker code was done by Nightbot\. I skidded it :\)/i ascii wide
    condition:
        pe.is_pe and $l
}

rule SRule13 {
    meta:
        author = "Smooth"
        description = "Detecta string: PE injector"
    strings:
        $m = /PE injector/i ascii wide
    condition:
        pe.is_pe and $m
}

rule SRule14 {
    meta:
        author = "Smooth"
        description = "Detecta string: name=\"SparkCrack.exe\""
    strings:
        $n = /name="SparkCrack\.exe"/i ascii wide
    condition:
        pe.is_pe and $n
}

rule SRule15 {
    meta:
        author = "Smooth"
        description = "Detecta string: starlight v1.0"
    strings:
        $o = /starlight v1\.0/i ascii wide
    condition:
        pe.is_pe and $o
}

rule SRule16 {
    meta:
        author = "Smooth"
        description = "Detecta string: Sapphire LITE Clicker"
    strings:
        $p = /Sapphire LITE Clicker/i ascii wide
    condition:
        pe.is_pe and $p
}

rule SRule17 {
    meta:
        author = "Smooth"
        description = "Detecta string: Striker.exe"
    strings:
        $q = /Striker\.exe/i ascii wide
    condition:
        pe.is_pe and $q
}

rule SRule18 {
    meta:
        author = "Smooth"
        description = "Detecta string: Cracked by Kangaroo"
    strings:
        $r = /Cracked by Kangaroo/i ascii wide
    condition:
        pe.is_pe and $r
}

rule SRule19 {
    meta:
        author = "Smooth"
        description = "Detecta string: Monolith Lite"
    strings:
        $s = /Monolith Lite/i ascii wide
    condition:
        pe.is_pe and $s
}

rule SRule20 {
    meta:
        author = "Smooth"
        description = "Detecta string: B.fagg0t0"
    strings:
        $t = /B\.fagg0t0/i ascii wide
    condition:
        pe.is_pe and $t
}

rule SRule21 {
    meta:
        author = "Smooth"
        description = "Detecta string: B.fag0"
    strings:
        $u = /B\.fag0/i ascii wide
    condition:
        pe.is_pe and $u
}

rule SRule22 {
    meta:
        author = "Smooth"
        description = "Detecta string: .fag1"
    strings:
        $v = /\.fag1/i ascii wide
    condition:
        pe.is_pe and $v
}

rule SRule23 {
    meta:
        author = "Smooth"
        description = "Detecta string: dream-injector"
    strings:
        $w = /dream-injector/i ascii wide
    condition:
        pe.is_pe and $w
}

rule SRule24 {
    strings:
        $x = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external\.pdb/i ascii wide
    condition:
        pe.is_pe and $x
}

rule SRule25 {
    strings:
        $y = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal\.pdb/i ascii wide
    condition:
        pe.is_pe and $y
}

rule SRule26 {
    meta:
        author = "Smooth"
        description = "Detecta string: UNICORN CLIENT"
    strings:
        $z = /UNICORN CLIENT/i ascii wide
    condition:
        pe.is_pe and $z
}

rule SRule27 {
    meta:
        author = "Smooth"
        description = "Detecta string: Adding delay to Minecraft"
    strings:
        $aa = /Adding delay to Minecraft/i ascii wide
    condition:
        pe.is_pe and $aa
}

rule SRule28 {
    meta:
        author = "Smooth"
        description = "Detecta string: rightClickChk.BackgroundImage"
    strings:
        $ab = /rightClickChk\.BackgroundImage/i ascii wide
    condition:
        pe.is_pe and $ab
}

rule SRule29 {
    meta:
        author = "Smooth"
        description = "Detecta string: UwU Client"
    strings:
        $ac = /UwU Client/i ascii wide
    condition:
        pe.is_pe and $ac
}

rule SRule30 {
    meta:
        author = "Smooth"
        description = "Detecta string: lithiumclient.wtf"
    strings:
        $ad = /lithiumclient\.wtf/i ascii wide
    condition:
        pe.is_pe and $ad
}

rule SRule31 {
    strings:
        $ae = /\bCLICKER\b/i ascii wide
    condition:
        pe.is_pe and $ae
}

rule KeyAuth
{
    meta:
        author = "Smooth"
        description = "Detecta strings relacionadas à KeyAuth API e panel clients"
    strings:
        $key1 = /keyauth\.win/i ascii wide
        $key2 = /https:\/\/keyauth\.win\/api\/1\.0\/\?/i ascii
        $key3 = "sessionid" ascii
        $key4 = "app_secret" ascii
        $key5 = "KeyAuthApp" ascii
        $key6 = "KeyAuthAPI" ascii
        $key7 = "key_auth_user_data" ascii
    condition:
        pe.is_pe and any of them
}


rule SRule32 {
    meta:
        author = "Smooth"
        description = "Detecta string: SpeedAutoClicker"
    strings:
        $ah = /SpeedAutoClicker/i ascii wide
    condition:
        pe.is_pe and $ah
}

rule SRule33 {
    meta:
        author = "Smooth"
        description = "Detecta string: Self Destruct"
    strings:
        $ai = /Self Destruct/i ascii wide
    condition:
        pe.is_pe and $ai
}

rule NULLClient {
    meta:
        author = "Smooth"
        description = "Detecta strings: six#0404, NullClient, Null Client"
    strings:
        $str1 = /six#0404/i ascii wide
        $str2 = /NullClient/i ascii wide
        $str3 = /Null Client/i ascii wide
    condition:
        pe.is_pe and any of them
}

rule WebHookPE {
    strings:
        $webhook = /discord\.com\/api\/webhooks\// nocase ascii wide
    condition:
        pe.is_pe and $webhook
}

rule WebHookAny {
    strings:
        $webhookj = /discord\.com\/api\/webhooks\// nocase ascii wide
    condition:
        $webhookj
}

rule WebHookJ
{
    meta:
        author = "Smooth"
        description = "Detecta URLs de WebHook do Discord"
    
    strings:
        $webhookj = /discord\.com\/api\/webhooks\// nocase ascii wide

    condition:
        $webhookj
}



rule SRule34 {
    meta:
        author = "Smooth"
        description = "Detecta string: NameTags"
    strings:
        $an = /NameTags/i ascii wide
    condition:
        pe.is_pe and $an
}

rule SRule35 {
    meta:
        author = "Smooth"
        description = "Detecta string: Monaco"
    strings:
        $ao = /Monaco/i ascii wide
    condition:
        pe.is_pe and $ao
}

rule SRule36 {
    meta:
        author = "Smooth"
        description = "Detecta string: Meduse.ac"
    strings:
        $ap = /Medusa\.ac/i ascii wide
    condition:
        pe.is_pe and $ap
}

rule SRule37 {
    meta:
        author = "Smooth"
        description = "Detecta string: Raid0"
    strings:
        $aq = /Raid0/i ascii wide
    condition:
        pe.is_pe and $aq
}

rule SRule38 {
    meta:
        author = "Smooth"
        description = "Detecta string: DoomsDay"
    strings:
        $ar = /DoomsDay/i ascii wide
    condition:
        pe.is_pe and $ar
}

rule SRule39 {
    meta:
        author = "Smooth"
        description = "Detecta string: koid"
    strings:
        $as = /koid/i ascii wide
    condition:
        pe.is_pe and $as
}

rule SRule40 {
    meta:
        author = "Smooth"
        description = "Detecta string: Exelon"
    strings:
        $at = /Exelon/i ascii wide
    condition:
        pe.is_pe and $at
}

rule SRule41 {
    meta:
        author = "Smooth"
        description = "Detecta string: Cyde.xyz ou polonium"
    strings:
        $au = /Cyde\.xyz/i ascii wide
        $av = /polonium/i ascii wide
    condition:
        pe.is_pe and ($au or $av)
}

rule AC
{
    meta:
        author = "Smooth"
        description = "Detecta variantes de autoclicker"

    strings:
        $variant = /auto[-_ ]?click(er)?/ nocase ascii wide

    condition:
        pe.is_pe and $variant
}

rule Obfuscated
{
    meta:
        author = "Smooth"
        date = "2025-06-09"
        description = "Detecta uso de packers e ofuscação comum em clients de Minecraft"

    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $the1 = "Themida" ascii
        $the2 = "WinLicense" ascii
        $confuser = "ConfusedByConfuserEx" ascii
        $dotfuscator = "DotfuscatorAttribute" ascii

    condition:
        pe.is_pe and any of them
}

rule PeDetect
{
    meta:
        author = "Smooth"
        date = "2025-06-09"
        description = "Detecta padrões comuns usados em PE Injectors"

    strings:
        $create_process = "CreateProcess" nocase
        $open_process = "OpenProcess" nocase
        $create_remote_thread = "CreateRemoteThread" nocase
        $virtual_alloc_ex = "VirtualAllocEx" nocase
        $write_process_memory = "WriteProcessMemory" nocase
        $virtual_protect_ex = "VirtualProtectEx" nocase
        $load_library = "LoadLibrary" nocase
        $get_proc_address = "GetProcAddress" nocase
        $inject_pattern1 = { 68 ?? ?? ?? ?? 6A 00 6A 00 FF 15 ?? ?? ?? ?? }

    condition:
        4 of ($create_process, $open_process, $create_remote_thread, $virtual_alloc_ex, $write_process_memory, $virtual_protect_ex, $load_library, $get_proc_address) or
        $inject_pattern1
}

rule SRule42 {
    strings:
        $sap1 = "sapphire.ac" ascii wide nocase
        $sap2 = "discord.sapphire.ac" ascii wide nocase

    condition:
        pe.is_pe and any of ($sap1, $sap2)
}

rule SRule43 {
    strings:
        $ds = /Dusk[\s_-]?Clicker/i ascii wide

    condition:
        pe.is_pe and $ds
}

rule SRule44 {
    strings:
        $kr = "karma.rip" ascii wide nocase

    condition:
        pe.is_pe and $kr
}

rule SRule45 {
    strings:
        $ec = /Eclipse[\s_-]?Clicker/i ascii wide

    condition:
        pe.is_pe and $ec
}

rule Wurst
{
    strings:
        $s1 = "Wurst" ascii nocase
    condition:
        $s1
}

rule LiquidBounce
{
    strings:
        $s1 = "LiquidBounce" ascii nocase
    condition:
        $s1
}

rule RavenWeave
{
    strings:
        $s1 = "RavenWeave" ascii nocase
    condition:
        $s1
}

rule Skilled
{
    strings:
        $sk1 = "0adjkfh31" ascii nocase
	$sk2 = "skilled" ascii nocase
	$sk3 = "SkilledClient.class" ascii nocase
	
    condition:
        any of them
}

rule Haru
{
    strings:
        $h1 = "Haru.class" ascii
    condition:
        $h1
}

rule Doomsday
{
    strings:
        $a1 = "doomsday" ascii nocase
        $a2 = "doomsday.com" ascii nocase
        $a3 = "Inject settings" ascii nocase
        $a4 = "loader settings" ascii nocase
        $a5 = "doomsdayclient.com" ascii nocase
        $a6 = "5GFV7PF7IN7FU" ascii nocase
        $a7 = "UT6kk" ascii nocase
	$a8 = "qUKsUd" ascii nocase
    condition:
        any of them
}


rule MD1
{
    strings:
        $a1 = "mods/vape" ascii nocase
    condition:
        $a1
}

rule MD2
{
    strings:
        $s1 = "modules/combat" ascii nocase
        $s2 = "modules/visuals" ascii nocase
    condition:
        $s1 or $s2
}

rule MD3
{
    strings:
        $a3 = "combat" ascii nocase
    condition:
        $a3
}


rule MD6
{
    strings:
        $cli = /auto[-_ ]?click(er)?/ nocase ascii

    condition:
        $cli
}

rule MD7
{
    strings:
        $a7 = "aim assist" ascii nocase
    condition:
        $a7
}

rule MD8
{
    strings:
        $a8 = "AimAssist" ascii nocase
    condition:
        $a8
}

rule Raven
{
    strings:
        $rv1 = "Raven" ascii
	$rv2 = "Raven.class" ascii
    condition:
        any of them
}

rule MD10
{
    strings:
        $a10 = "Bhop" ascii 
    condition:
        $a10
}

rule MD11
{
    strings:
        $s1 = "killaura" ascii nocase
        
    condition:
        any of them
}

rule MD13
{
    strings:
        $s1 = "velocityhack" ascii nocase
    condition:
        $s1
}

rule MD14
{
    strings:
        $s1 = "autoblock" ascii nocase
    condition:
        $s1
}

rule MD15
{
    strings:
        $s1 = "fastplace" ascii nocase
    condition:
        $s1
}

rule MD16
{
    strings:
        $s1 = "fastbreak" ascii nocase
    condition:
        $s1
}

rule MD17
{
    strings:
        $s1 = "antiknockback" ascii nocase
    condition:
        $s1
}

rule MD18
{
    strings:
        $s1 = "speedhack" ascii nocase
    condition:
        $s1
}

rule MD19
{
    strings:
        $s1 = "triggerbot" ascii nocase
    condition:
        $s1
}

rule MaliciousThreads {
    strings:
        $thread1 = "CreateThread" nocase
        $thread2 = "CreateThreadNow" nocase
        $thread3 = "RegisterThread" nocase

        $susp1 = "LoadLibraryA" nocase
        $susp2 = "GetProcAddress" nocase
        $susp3 = "VirtualAlloc" nocase
        $susp4 = "VirtualProtect" nocase
        $susp5 = "WriteProcessMemory" nocase

        $shell1 = /ShellExecute[A-Za-z0-9_]+/ nocase
        $shell2 = /WinExec/ nocase

    condition:
        3 of ($thread*) and
        2 of ($susp*) and
        any of ($shell*)
}

rule HitDelayPE
{
    strings:
        $a = /no[\s\-_]*hit[\s\-_]*delay/i
        $b = /hit[\s\-_]*delay[\s\-_]*fix/i
        $c = /Hit[\s\-_]*Delay/i
        $d = /No[\s\-_]*Hit[\s\-_]*Delay/i
    condition:
        pe.is_pe and any of them
}

rule HitDelayAny
{
    strings:
        $a = /no[\s\-_]*hit[\s\-_]*delay/i
        $b = /hit[\s\-_]*delay[\s\-_]*fix/i
        $c = /Hit[\s\-_]*Delay/i
        $d = /No[\s\-_]*Hit[\s\-_]*Delay/i
    condition:
        any of them
}

rule HitDelayBLC
{
    strings:
        $blcHit = "jvm.dll not found" ascii wide nocase
    condition:
        any of them
}


rule NoJumpDelayPE
{
    strings:
        $nj1 = /no[\s\-_]*jump[\s\-_]*delay/i
    condition:
        pe.is_pe and $nj1
}

rule NoJumpDelayAny
{
    strings:
        $nj1 = /no[\s\-_]*jump[\s\-_]*delay/i
    condition:
        $nj1
}
