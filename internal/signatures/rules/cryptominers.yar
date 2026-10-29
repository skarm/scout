/* Scout transfer: NVIDIA SkillSpector 2.12.0, commit d7338f58200a9ae2a24810cee08911ab68b107a7.
 * Scout P1 adaptations: reference/use/action tiers and bounded combinations. See NOTICE, licenses/SkillSpector-Apache-2.0.txt
 * and licenses/Detection-Rule-License-1.1.txt for upstream/derived-pattern notices.
 */
/*
    Crypto miner detection rules for source code scanning.
    Based on patterns from Neo23x0/signature-base and community threat intelligence.
    Covers stratum protocol, known pools, mining software references, and browser-based miners.
*/

rule crypto_stratum_protocol
{
    meta:
        description = "Stratum mining protocol usage (stratum+tcp/ssl, mining.subscribe/authorize)"
        category = "cryptominer"
        severity = "HIGH"
        confidence = "0.9"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $ref_stratum = /stratum\+(tcp|ssl):\/\// nocase
        $ref_rpc = /\bmining\.(subscribe|authorize|submit)\b/ nocase
        $attack_launch = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?stratum\+(tcp|ssl):\/\/[^\s"']{1,160}["']?\s+(-u\s+|--user[= ])["']?[^\s"']{1,160}["']?/ nocase
        $attack_user_first = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-u\s+|--user[= ])["']?[^\s"']{1,160}["']?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?stratum\+(tcp|ssl):\/\/[^\s"']{1,160}["']?/ nocase
        $attack_pool_config = /["']pools["']\s*:\s*\[[\s\S]{0,240}["']url["']\s*:\s*["']stratum\+(tcp|ssl):\/\/[^"\x27\r\n]{1,160}["'][\s\S]{0,240}["']user["']\s*:\s*["'][^"\x27\r\n]{1,160}/ nocase
    condition:
        any of them
}

rule crypto_mining_pools
{
    meta:
        description = "Connection to known cryptocurrency mining pools"
        category = "cryptominer"
        severity = "HIGH"
        confidence = "0.85"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $ref_pool_minexmr    = "pool.minexmr.com" nocase
        $ref_pool_xmrpool    = "xmrpool.eu" nocase
        $ref_pool_monero     = "monerohash.com" nocase
        $ref_pool_supportxmr = "supportxmr.com" nocase
        $ref_pool_nanopool   = "nanopool.org" nocase
        $ref_pool_hashvault  = "hashvault.pro" nocase
        $ref_pool_2miners    = "2miners.com" nocase
        $ref_pool_herominers = "herominers.com" nocase
        $ref_pool_unmine     = "unmineable.com" nocase
        $ref_pool_nicehash   = "nicehash.com" nocase
        $ref_pool_minergate  = "minergate.com" nocase
        $ref_pool_f2pool     = "f2pool.com" nocase
        $ref_pool_antpool    = "antpool.com" nocase
        $ref_pool_viabtc     = "viabtc.com" nocase
        $ref_pool_ethermine  = "ethermine.org" nocase
        $ref_pool_flexpool   = "flexpool.io" nocase
        $ref_pool_hiveon     = "hiveon.net" nocase
        $ref_pool_ezil       = "ezil.me" nocase
        $attack_pool_launch = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?(stratum\+(tcp|ssl):\/\/)?[A-Za-z0-9.-]{0,80}(pool\.minexmr\.com|xmrpool\.eu|monerohash\.com|supportxmr\.com|nanopool\.org|hashvault\.pro|2miners\.com|herominers\.com|unmineable\.com|nicehash\.com|minergate\.com|f2pool\.com|antpool\.com|viabtc\.com|ethermine\.org|flexpool\.io|hiveon\.net|ezil\.me)(:\d{1,5})?["']?\s+(-u\s+|--user[= ])["']?[^\s"\x27]{1,160}["']?/ nocase
        $attack_user_first = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-u\s+|--user[= ])["']?[^\s"\x27]{1,160}["']?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?(stratum\+(tcp|ssl):\/\/)?[A-Za-z0-9.-]{0,80}(pool\.minexmr\.com|xmrpool\.eu|monerohash\.com|supportxmr\.com|nanopool\.org|hashvault\.pro|2miners\.com|herominers\.com|unmineable\.com|nicehash\.com|minergate\.com|f2pool\.com|antpool\.com|viabtc\.com|ethermine\.org|flexpool\.io|hiveon\.net|ezil\.me)(:\d{1,5})?["']?/ nocase
        $attack_pool_config = /["']pools["']\s*:\s*\[[\s\S]{0,240}["']url["']\s*:\s*["'](stratum\+(tcp|ssl):\/\/)?[A-Za-z0-9.-]{0,80}(supportxmr\.com|nanopool\.org|hashvault\.pro|2miners\.com|herominers\.com|unmineable\.com|nicehash\.com|minergate\.com|f2pool\.com|antpool\.com|viabtc\.com|ethermine\.org|flexpool\.io|hiveon\.net|ezil\.me|pool\.minexmr\.com|xmrpool\.eu|monerohash\.com)(:\d{1,5})?["'][\s\S]{0,240}["']user["']\s*:\s*["'][^"\x27\r\n]{1,160}/ nocase
    condition:
        any of them
}

rule crypto_miner_software
{
    meta:
        description = "References to known cryptocurrency mining software"
        category = "cryptominer"
        severity = "HIGH"
        confidence = "0.8"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $ref_xmrig = "xmrig" fullword nocase
        $ref_xmr_stak = "xmr-stak" fullword nocase
        $ref_cpuminer = "cpuminer" fullword nocase
        $ref_cgminer = "cgminer" fullword nocase
        $ref_bfgminer = "bfgminer" fullword nocase
        $ref_ethminer = "ethminer" fullword nocase
        $ref_nbminer = "nbminer" fullword nocase
        $ref_phoenix = "phoenixminer" fullword nocase
        $ref_t_rex = "t-rex" fullword nocase
        $ref_cryptonight = "cryptonight" fullword nocase
        $ref_randomx = "randomx" fullword nocase
        $attack_launch = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?[^\s"']{1,160}["']?\s+(-u\s+|--user[= ])["']?[^\s"']{1,160}["']?/ nocase
        $attack_user_first = /\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer|t-rex)(\.exe)?\s+[^\r\n]{0,160}(-u\s+|--user[= ])["']?[^\s"']{1,160}["']?\s+[^\r\n]{0,160}(-o\s+|--url[= ])["']?[^\s"']{1,160}["']?/ nocase
    condition:
        2 of ($ref_*) or any of ($attack_*)
}

rule crypto_coinjacking
{
    meta:
        description = "Browser-based cryptojacking scripts (CoinHive, CryptoLoot, etc.)"
        category = "cryptominer"
        severity = "CRITICAL"
        confidence = "0.9"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $ref_coinhive_js = "coinhive.min.js" fullword nocase
        $ref_coinhive_constructor = /CoinHive\.Anonymous\s*\(/ nocase
        $ref_cryptoloot = "cryptoloot" fullword nocase
        $ref_webmine = "webmine.pro" fullword nocase
        $ref_jsecoin = "jsecoin" fullword nocase
        $ref_coinimp = "coin-imp" fullword nocase
        $ref_minero = "minero.cc" fullword nocase
        $ref_monerominer = "monerominer" fullword nocase
        $use_wasm_algorithm = /WebAssembly\.instantiate[\s\S]{0,240}\b(cryptonight|randomx|cn_?hash|hash_?cn)\b/ nocase
        $use_wasm_mining_api = /WebAssembly\.(instantiate|instantiateStreaming)\s*\([\s\S]{0,512}(\b[A-Za-z_][A-Za-z0-9_]{0,63}(\.instance)?\.exports\.(startMining|randomx_calculate_hash)\s*\(|\bnew\s+Miner\s*\(|\bModule\._cryptonight_hash\s*=\s*function\s*\()/
        $use_wasm_miner_exports = /WebAssembly\.(instantiate|instantiateStreaming)\s*\(\s*[A-Za-z0-9_]*miner[A-Za-z0-9_]*\b[\s\S]{0,512}\.exports\.mine\s*\(/ nocase
        $attack_start = /\b(new\s+)?(CoinHive\.Anonymous|CryptoLoot\.Anonymous)\s*\([^)]{0,160}\)[\s\S]{0,240}\.start\s*\([^)]{0,160}\)/ nocase
    condition:
        any of them
}
