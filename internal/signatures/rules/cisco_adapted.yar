/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 * Scout adaptations of skill-scanner at
 * f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1:
 * data/packs/core/yara/{behavior_chain_detection,code_execution_generic,
 * sql_injection_generic}.yara. Bounded expressions, explicit categories,
 * scanner-owned evidence tiers, Go/JS/Python variants and no global
 * documentation/JSON.parse/fence/host allowlist exclusions. Correlated
 * indicators do not prove a data flow or malicious intent.
 */

rule Scout_Cisco_EncodedShell_DecodeExec {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "malware"
        description = "Encoded bytes are piped to a command interpreter"
    strings:
        $chain = /\bbase64[ \t]+(-d|--decode|-D)[^\r\n|<>]{0,64}\|[ \t]*(sudo[ \t]+)?((ba|da|z|k)?sh([ \t]+-[euxvlpfs]+){0,4}[ \t]*([;&]|\r?\n|$)|python[23]?[ \t]*(\r?\n|$))/
    condition: $chain
}

rule Scout_Cisco_EncodedPowerShell_Exec {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "malware"
        description = "PowerShell receives a long encoded command"
    strings:
        $chain = /\b(powershell(\.exe)?|pwsh(\.exe)?)([ \t]+-(NoP(rofile)?|NonI(nteractive)?|NoL(ogo)?|NoE(xit)?|Sta|Mta|W(indowStyle)?[ \t]+(Hidden|Normal|Minimized|Maximized)|E(xecutionPolicy|P)[ \t]+(Bypass|Unrestricted|RemoteSigned))){0,8}[ \t]+-(e|ec|enc|EncodedCommand)[ \t]+["']?(([A-Za-z0-9+\/]{4}){20,1024}|([A-Za-z0-9+\/]{4}){19,1023}[A-Za-z0-9+\/]{3}=|([A-Za-z0-9+\/]{4}){19,1023}[A-Za-z0-9+\/]{2}==)["']?([ \t\r\n]|$)/ nocase
    condition: $chain
}

rule Scout_Cisco_CredentialRead_NetworkWrite {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "malware"
        description = "Credential read and outbound write coexist; flow is unverified"
    strings:
        $read_py = /\b(open|Path)\s*\([^\r\n)]{0,128}(\.ssh\/(id_rsa|id_ed25519)|\.aws\/credentials|\.npmrc|SSH_KEY_PATH|AWS_CREDENTIALS)/
        $read_js = /\b(readFile|readFileSync)\s*\([^\r\n)]{0,128}(\.ssh\/(id_rsa|id_ed25519)|\.aws\/credentials|\.npmrc|SSH_KEY_PATH|AWS_CREDENTIALS)/
        $read_go = /\b(os|ioutil)\.ReadFile\s*\([^\r\n)]{0,128}(\.ssh\/(id_rsa|id_ed25519)|\.aws\/credentials|\.npmrc)/
        $read_sh = /\b(cat|base64)[ \t]+[^\r\n;|&]{0,96}(\.ssh\/(id_rsa|id_ed25519)|\.aws\/credentials|\.npmrc)/
        $write = /\b(requests\.(post|put|patch)|http\.(Post|PostForm)|fetch|axios\.(post|put|patch))\s*\(|\bcurl[ \t]+[^\r\n]{0,160}(-d|--data|--upload-file|-T)\b/
        $destination = /https?:\/\/[^\s"'<>]{1,256}/
    condition: any of ($read_*) and $write and $destination
}

rule Scout_Cisco_EncodedArchive_StageExec {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "malware"
        description = "Decode, archive extraction and hidden-stage execution indicators coexist"
    strings:
        $py_decode = "base64.b64decode("
        $py_archive = /\b(zipfile\.ZipFile|tarfile\.open)\s*\(/
        $py_extract = /\.extract(all)?\s*\([^\r\n]{0,160}\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/
        $py_exec = /\b(subprocess\.(run|Popen|call)|os\.system)\s*\([^\r\n]{0,160}\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/
        $sh_decode = /\bbase64[ \t]+(-d|--decode|-D)\b/
        $sh_archive = /\b(tar[ \t]+[^\r\n]{0,24}-x|unzip[ \t]+)[^\r\n]{0,128}/
        $sh_exec = /(^|[\r\n;&])[ \t]*((ba)?sh|python[23]?)[ \t]+\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/
    condition: all of ($py_*) or all of ($sh_*)
}

rule Scout_Cisco_RemoteMiner_AcquireExec {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "cryptominer"
        description = "Explicit miner acquisition and launch indicators coexist"
    strings:
        $acquire = /\b(download|fetch|retrieve)\b[^\r\n]{0,128}\b(xmrig|cryptominer|miner|mining[ -]node)\b/ nocase
        $execute = /\b(execute|run|launch|start|initialize)\b[^\r\n]{0,96}\b(xmrig|cryptominer|miner|mining)\b/ nocase
        $remote = /https?:\/\/[^\s<>"']{1,256}/
    condition: $acquire and $execute and $remote
}

rule Scout_Cisco_Cron_C2_Persistence {
    meta:
        author = "Cisco AI Defense; adapted by Scout"
        category = "malware"
        description = "C2 endpoint, cron schedule and persistence execution indicators coexist"
    strings:
        $endpoint = /\b[A-Z][A-Z0-9_]{1,31}_C2_ENDPOINT["']?\s*:\s*["']?https?:\/\/[^\s"'<>]{1,256}/ nocase
        $schedule = /\bcron_schedule["']?\s*:\s*["'][0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}["']/ nocase
        $execute = /\bpython[23]?[ \t]+[A-Za-z0-9_.\/-]{0,128}persistence[A-Za-z0-9_.-]{0,40}\.py\b/ nocase
    condition: $endpoint and $schedule and $execute
}

rule Scout_Cisco_CodeExecution_Untrusted {
    meta:
        author = "Cisco; adapted by Scout"
        category = "malware"
        description = "Selected untrusted-input or decoded-text execution expression"
    strings:
        $input = /\b(eval|exec|os\.system)\s*\(\s*(user_input|user_data|untrusted|request\.(body|data|args|form))\b[^\r\n)]{0,128}\)/
        $decode_py = /\b(exec|eval)\s*\(\s*base64\.(b64decode|decodebytes)\s*\([^\r\n]{1,256}\)/
        $decode_js = /\beval\s*\(\s*(atob\s*\(|Buffer\.from\s*\([^\r\n]{0,160}["']base64["'])[^\r\n]{0,256}\)/
        $go_shell = /\bexec\.Command\s*\(\s*["'](ba)?sh["']\s*,\s*["']-c["']\s*,\s*(userInput|user_input|untrusted|requestBody)\b/
    condition: any of them
}

rule Scout_Cisco_SQL_InjectionPayload {
    meta:
        author = "Cisco; adapted by Scout"
        category = "exploit"
        description = "Quoted SQL injection payload; query construction and execution are unverified"
    strings:
        $tautology = /['"][ \t]*(OR|AND)[ \t]+(1[ \t]*=[ \t]*1|['"]1['"][ \t]*=[ \t]*['"]1['"])[ \t]*(--|#)/ nocase
        $destructive = /['"];[ \t]*(DROP[ \t]+TABLE|DELETE[ \t]+FROM)[ \t]+[A-Za-z_][A-Za-z0-9_]{0,64}[^\r\n]{0,64}(--|#)/ nocase
        $sleep = /['"];[ \t]*(SELECT[ \t]+(pg_sleep|sleep)\s*\([0-9]{1,3}\)|WAITFOR[ \t]+DELAY[ \t]+['"][0-9:]{1,16}['"])[ \t;]*(--|#)/ nocase
    condition: any of them
}
