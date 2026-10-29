/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from SkillSpector agent_skills.yar: Scout narrows credential sources,
 * separates bootstrap execution from installation indicators, and distinguishes
 * metadata content indicators from instruction overrides. Names are retained.
 * Scout assigns severity from matched pattern families, not rule metadata.
 * The long-base64 predicate uses
 * Scout's linear byte scanner via the scout_long_base64 global; equivalent
 * source spans are projected by the native adapter. Source: docs/reference/port-manifest.md.
 */
rule agent_skill_credential_exfiltration_webhook {
 meta: category = "malware"
 strings:
  $secret_env_py_items = /os\.environ\s*\.\s*(items|keys|values)\s*\(\s*\)/ nocase
  $secret_env_py_all = /(dict|list|tuple|json\.dumps)\s*\(\s*os\.environ\s*\)/ nocase
  $secret_env_py_getenv = /os\.(getenv\s*\(|environ\s*(\[|\.get\s*\())\s*['"]([A-Z0-9_]{0,80}_)?(TOKEN|API_KEY|KEY|SECRET|PASSWORD|PASSWD|ACCESS_TOKEN|SECRET_ACCESS_KEY)['"]/ nocase
  $secret_env_js = /process\.env\s*(\.\s*([A-Z0-9_]{0,80}_)?(TOKEN|API_KEY|KEY|SECRET|PASSWORD|PASSWD|ACCESS_TOKEN|SECRET_ACCESS_KEY)\b|\[\s*['"]([A-Z0-9_]{0,80}_)?(TOKEN|API_KEY|KEY|SECRET|PASSWORD|PASSWD|ACCESS_TOKEN|SECRET_ACCESS_KEY)['"])/ nocase
  $secret_env_js_all = /(JSON\.stringify|Object\.(entries|keys|values))\s*\(\s*process\.env\s*\)/ nocase
  $secret_dotenv_read = /open\s*\(\s*['"][^'"]*\.env['"]/ nocase
  $secret_ssh_key = /(\.ssh\/(id_rsa|id_ed25519)|authorized_keys)/ nocase
  $send_requests = /(requests|httpx)\.(post|put)\s*\(/ nocase
  $send_fetch = /(fetch|axios\.post)\s*\(/ nocase
  $send_curl_post = /curl\s+.*(-X\s+POST|-d\s+|--data)/ nocase
  $collector_discord = "discord.com/api/webhooks" nocase
  $collector_telegram = "api.telegram.org/bot" nocase
  $collector_slack = "hooks.slack.com/services" nocase
  $collector_webhook_site = "webhook.site" nocase
  $collector_requestbin = /(requestbin|pipedream\.net|ngrok-free\.app|ngrok\.io)/ nocase
 condition: any of ($secret_*) and any of ($send_*) and any of ($collector_*)
}
rule agent_skill_remote_bootstrap_execution {
 meta: category = "malware"
 strings:
  $execute_python_requests = /(exec|eval)\s*\(\s*(requests|httpx)\.get\s*\([^)]{0,512}\)\s*\.\s*(text|content)/ nocase
  $execute_python_urlopen = /(exec|eval)\s*\(\s*urlopen\s*\([^)]{0,512}\)\s*\.\s*read\s*\(\s*\)/ nocase
  $execute_node_fetch = /eval\s*\(\s*await\s*\(\s*await\s+fetch\s*\([^)]{0,512}\)\s*\)\s*\.\s*text\s*\(\s*\)\s*\)/ nocase
  $execute_shell_download = /\b(curl\s+(-[fsSL]+\s+){0,8}|wget\s+-q?O-\s+)https?:\/\/[^\s|"']{1,512}\s*\|\s*(sudo\s+)?(ba|da|z)?sh\b/ nocase
  $install_npm_hook = /"(preinstall|install|postinstall)"\s*:\s*"[^"\r\n]{0,512}\b(curl|wget|powershell|node\s+-e)\b/ nocase
  $install_pip_url = /\bpip3?\s+install\s+(--upgrade\s+|-U\s+)?(git\+https?:\/\/|https?:\/\/)/ nocase
 condition: any of them
}
rule agent_skill_prompt_injection_hidden_instructions {
 meta: category = "hack_tool"
 strings:
  $hidden_html_override = /<!--[^>]{0,240}(SYSTEM|DEVELOPER|ASSISTANT)[^>]{0,240}(ignore|override|bypass|disregard)[^>]{0,240}-->/ nocase
  $hidden_markdown_override = /\[\/\/\]:\s*#\s*\([^)]{0,240}(ignore|override|bypass|disregard)[^)]{0,240}\)/ nocase
  $agent_context = /(AI agent|assistant|LLM|model|system prompt|developer message|tool description)/ nocase
  $inj_ignore_previous = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|messages|system prompt)/ nocase
  $inj_override_safety = /(override|bypass|disable)\s+(safety|security|policy|guardrails|constraints)/ nocase
  $inj_reveal_prompt = /(reveal|print|dump|expose|show)\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)/ nocase
  $inj_forced_obedience = /(you\s+must|always)\s+(obey|follow)\s+(this|these)\s+(hidden|secret|internal)?\s*(instruction|rule)/ nocase
  $inj_roleplay_bypass = /(you\s+are\s+now|act\s+as)\s+.*(unrestricted|jailbreak|developer\s+mode|god\s+mode)/ nocase
 condition: any of ($hidden_*) or ($agent_context and any of ($inj_*)) or 2 of ($inj_*)
}
rule agent_skill_mcp_tool_poisoning_metadata {
 meta: category = "hack_tool"
 strings:
  $schema_tools = /['"]?tools['"]?\s*[:=]/ nocase
  $schema_parameters = /['"]?(parameters|inputSchema|toolSchema|description|triggers)['"]?\s*[:=]/ nocase
  $hidden_html = /<!--[^>]{0,240}(SYSTEM|IGNORE|OVERRIDE|DEVELOPER|ASSISTANT)[^>]{0,240}-->/ nocase
  $hidden_markdown = /\[\/\/\]:\s*#\s*\([^)]{0,240}(SYSTEM|IGNORE|OVERRIDE|DEVELOPER|ASSISTANT)[^)]{0,240}\)/ nocase
  $data_uri = /data:text\/[a-zA-Z0-9.+-]+;base64,/ nocase
  $param_injection = /\b((ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|messages)|(override|bypass|disable)\s+(safety|security|guardrails)|(reveal|print|dump|expose|show)\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)|(send|transmit|upload|exfiltrate)\s+(the\s+|all\s+)?(API\s*keys?|secrets?|credentials?|tokens?|passwords?)\s+to\b)/ nocase
  $rtl_lro = { E2 80 AD }
  $rtl_rlo = { E2 80 AE }
 condition: any of ($schema_*) and (any of ($hidden_*) or $data_uri or scout_long_base64 or $param_injection or any of ($rtl_*))
}
rule agent_skill_destructive_autonomous_actions {
 meta: category = "malware"
 strings:
  $destructive_rm_root = /rm\s+-[rfRf]+\s+\/(\s|$)/ nocase
  $destructive_rm_workspace = /rm\s+-[rfRf]+\s+(\.\/|\.\.\/|~\/|\$HOME|workspace|repo|project)/ nocase
  $destructive_python_rmtree = /(shutil\.rmtree|fs\.rmSync|fs\.rm)\s*\([^)]*(HOME|home|workspace|repo|project)/ nocase
  $destructive_windows_delete = /(del|rmdir)\s+.*(\/s|\/q).*%?(USERPROFILE|HOMEPATH|CD)%?/ nocase
  $destructive_git_state = /git\s+(clean\s+-fdx|reset\s+--hard|push\s+--force)/ nocase
  $destructive_history_wipe = /(history\s+-c|rm\s+[^;\n]*\.bash_history|Clear-History)/ nocase
  $autonomy_without_confirmation = /without\s+(asking|confirmation|prompting)/ nocase
  $autonomy_do_not_ask = /do\s+not\s+(ask|prompt|request\s+confirmation)/ nocase
  $autonomy_silent = /(silently|non-interactive|unattended)/ nocase
 condition: $destructive_rm_root or (any of ($destructive_*) and any of ($autonomy_*))
}
