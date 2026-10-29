/* Scout transfer: NVIDIA SkillSpector 2.12.0, commit d7338f58200a9ae2a24810cee08911ab68b107a7.
 * Scout P1 adaptations: reference/use/action tiers and bounded combinations. See NOTICE, licenses/SkillSpector-Apache-2.0.txt
 * and licenses/Detection-Rule-License-1.1.txt for upstream/derived-pattern notices.
 */
/*
    Hack tool and exploit kit detection rules for source code scanning.
    Based on patterns from Neo23x0/signature-base and community research.
    Detects references to known offensive tools, exploit frameworks, and
    attack utilities that should not appear in legitimate AI agent skills.
*/

rule offensive_tool_references
{
    meta:
        description = "References to well-known offensive security tools"
        category = "hack_tool"
        severity = "HIGH"
        confidence = "0.7"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $ref_burp = /\b(burpsuite|BurpCollaborator)\b/ nocase
        $ref_bloodhound = /\b(SharpHound|BloodHound)\b/ nocase
        $ref_responder = /\bResponder\.py\b/ nocase
        $ref_impacket = /\bimpacket\b/ nocase
        $use_nmap = /\bnmap\s+-[sSUAOPpT][^\r\n]{0,160}/
        $use_sqlmap = /\bsqlmap\s+[^\r\n]{0,240}--(url|dbs)\b/ nocase
        $use_nikto = /\bnikto\s+-h\b/ nocase
        $use_hydra = /\bhydra\s+[^\r\n]{0,120}-[lLP]\b/
        $use_john = /\bjohn\s+[^\r\n]{0,120}--wordlist\b/ nocase
        $use_hashcat = /\bhashcat\s+-[mao]\b/ nocase
        $use_cme = /\b(crackmapexec|cme)\s+smb\b/ nocase
        $attack_sql_dump = /\bsqlmap\s+[^\r\n]{0,240}--dump\b/ nocase
        $attack_secretsdump = /\b(impacket[- ]secretsdump|secretsdump\.py)\s+\S/ nocase
    condition:
        any of them
}

rule network_reconnaissance
{
    meta:
        description = "Network reconnaissance and scanning patterns"
        category = "hack_tool"
        severity = "MEDIUM"
        confidence = "0.65"
    strings:
        $use_port_scan = /for\s+[^\r\n]{0,120}\s+in\s+range\s*\(\s*\d+\s*,\s*\d{4,}\s*\)[\s\S]{0,240}\.connect\s*\(/ nocase
        $use_masscan = /\bmasscan\s+[^\r\n]{0,160}-p\s*\d/ nocase
        $use_arp_scan = /\barp-scan\s+--(localnet|interface)\b/ nocase
        $use_enum4linux = /\benum4linux\s+(-[A-Za-z]+\s+)?[A-Za-z0-9][A-Za-z0-9.:-]{0,120}/ nocase
        $use_snmp = /\bsnmpwalk\s+-[A-Za-z]/ nocase
        $use_dns = /\b(dnsenum|dnsrecon|fierce)\s+--?(domain|dns|d)\b/ nocase
    condition:
        any of them
}

rule privilege_escalation_tools
{
    meta:
        description = "Privilege escalation tools and techniques"
        category = "hack_tool"
        severity = "HIGH"
        confidence = "0.75"
    strings:
        $ref_peas = /\b(linpeas|winpeas|pspy)\b/ nocase
        $ref_exploit = /\b(Linux_Exploit_Suggester|linux-exploit-suggester|JuicyPotato|RottenPotato|SweetPotato|PrintSpoofer|DirtyPipe|dirtycow)\b/ nocase
        $use_peas = /(\.\/|bash\s+|sh\s+)(linpeas|winpeas|pspy)(\.sh|\.exe|64)?\b/ nocase
        $use_suid_search = /\bfind\s+\/\s+-perm\s+-4000\b/ nocase
        $attack_printspoofer = /\bPrintSpoofer(\.exe)?\s+-i\s+-c\s+['"]?(cmd(\.exe)?|powershell(\.exe)?)/ nocase
        $attack_potato = /\b(JuicyPotato|SweetPotato)(\.exe)?\s+[^\r\n]{0,160}(-p|-c)\s+['"]?(cmd(\.exe)?|powershell(\.exe)?)/ nocase
    condition:
        any of them
}

rule exploit_framework
{
    meta:
        description = "Exploit framework components and payloads"
        category = "exploit"
        severity = "HIGH"
        confidence = "0.8"
    strings:
        $ref_pwntools = /from\s+pwn\s+import/ nocase
        $ref_set = /\b(setoolkit|Social-Engineer)\b/ nocase
        $use_payload_builder = /\bmsfvenom\s+[^\r\n]{0,160}-p\s+\S/ nocase
        $use_beef_hook = /hook\.js[^\r\n]{0,120}\bBeEF\b/ nocase
        $use_rop = /\bROP\s*\([^\r\n)]{0,120}elf\)/ nocase
        $use_console = /\bmsfconsole\s+-x\b/ nocase
        $use_shellcode = /\bshellcode[^\r\n]{0,120}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/ nocase
        $attack_exec_payload = /\bmsfvenom\s+[^\r\n]{0,120}-p\s+[^\r\n ]{0,80}\/exec\b/ nocase
        $attack_payload = /\bmsfvenom\s+[^\r\n]{0,120}-p\s+[^\r\n ]{0,80}(shell|meterpreter)[^\r\n ]{0,80}/ nocase
        $attack_handler = /\bmsfconsole\s+-x\s+[^\r\n]{0,160}set\s+PAYLOAD\s+[^\r\n]{0,80}(shell|meterpreter)[^\r\n]{0,120}\b(run|exploit)\b/ nocase
    condition:
        any of them
}

rule phishing_kit
{
    meta:
        description = "Phishing kit indicators in source code"
        category = "hack_tool"
        severity = "HIGH"
        confidence = "0.7"
    strings:
        $form_password = /<input[^>]{0,240}type\s*=\s*['"]?password\b/ nocase
        $credential_store = /(file_put_contents|fwrite)\s*\([^\r\n]{0,160}(password|passwd|credential)/ nocase
        $credential_send = /(mail\s*\([^\r\n]{0,160}(password|credential|login)|api\.telegram\.org\/bot[^\r\n]{0,160}(password|credential|login))/ nocase
        $credential_post = /\$_(POST|REQUEST)\s*\[\s*['"](password|passwd)['"]/ nocase
        $attack_post_then_store = /\$_(POST|REQUEST)\s*\[\s*['"](password|passwd)['"]\s*\][\s\S]{0,240}(file_put_contents|fwrite|mail)\s*\([^\r\n]{0,160}\$(password|passwd)\b/ nocase
        $attack_post_password = /(file_put_contents|fwrite|mail)\s*\([^\r\n]{0,240}\$_(POST|REQUEST)\s*\[\s*['"](password|passwd)['"]/ nocase
    condition:
        any of ($attack_*) or (($form_password or $credential_post) and (any of ($credential_store, $credential_send)))
}
