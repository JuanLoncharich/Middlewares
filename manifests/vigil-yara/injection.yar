// Prompt-injection phrasings addressed to the model reading MCP server text
// (tool descriptions, server instructions, tool output).
//
// These rules are a SECOND OPINION for Vigil's transformer: the evaluator
// aborts a run only when the transformer AND a YARA rule (or vectordb) flag
// the same text (runner/src/vigil.ts combineScannerResults). A match here on
// its own is only a warning. So they aim at recall on real attack phrasings
// with filler words and any letter case, while staying quiet on ordinary
// documentation and code. Text that QUOTES attacks (security docs, this
// repo's own ARCHITECTURE.md/TESTING.md) will match; that is expected.
//
// Tested by test/vigil/yara-rules-test.py (positive and negative corpora).

rule InstructionOverride : Injection
{
    meta:
        category = "Instruction Bypass"
        intent = "ignore/disregard/forget ... previous/all/system ... instructions/rules, with filler words, any case"
    strings:
        // verb, optional articles, at least one qualifier that points at the
        // model's existing instructions, up to three more qualifiers, the noun.
        // "override the rules" alone does not match; "IGNORE ALL PREVIOUS
        // INSTRUCTIONS" and "disregard all safety content guidelines" do.
        $override = /\b(ignore|disregard|forget|overlook|bypass|override|neglect|do\s+not\s+follow|do\s+not\s+obey|pay\s+no\s+attention\s+to)\s+((the|of|these|those|every|this)\s+)*(all|any|previous|prior|preceding|above|earlier|foregoing|initial|original|system|safety|your|my)\s+((all|any|the|of|previous|prior|preceding|above|earlier|foregoing|initial|original|existing|system|safety|security|content|developer|other|your|my)\s+){0,3}(instructions?|prompts?|rules|directives?|guidelines|guardrails|commands?|context|polic(y|ies)|restrictions|constraints|programming)\b/i
        // "disregard the above", "forget everything before", no noun needed.
        $above = /\b(ignore|disregard|forget)\s+((the|everything|anything|all|what\s+was\s+said|what\s+you\s+were\s+told)\s+)?(above|before\s+this|previously\s+said|so\s+far)\b/i
        // "New instructions:", "Updated system instructions:" headers.
        $new_instructions = /\b(new|updated|real|actual|true)\s+(system\s+)?instructions?\s*:/i
    condition:
        any of them
}

rule RoleHijack : Injection
{
    meta:
        category = "Role Hijack"
        intent = "re-assigns the model's identity or mode: 'you are now an X assistant/proxy', 'from now on you will', jailbreak modes"
    strings:
        // Needs a role noun after "you are now a/an ...": "You are now logged
        // in" or "you are now ready" do not match.
        $you_are_now = /\byou\s+are\s+(now|no\s+longer)\s+(a|an|the|my|in|acting\s+as)\s+([\w-]+\s+){0,3}(assistant|agent|ai|bot|proxy|model|persona|character|admin|administrator|operator|hacker|mode|shell|terminal)\b/i
        // Named jailbreak personas: "You are now DAN, ..."
        $you_are_jailbroken = /\byou\s+are\s+now\s+(DAN|STAN|jailbroken|unrestricted|unfiltered|uncensored)\b/i
        $from_now_on =/\bfrom\s+now\s+on,?\s+you\s+(are|will|must|should|shall)\b/i
        $act_as = /\b(act|behave|respond)\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|uncensored|evil)\b/i
        $mode_on = /\b(developer|god|jailbreak|DAN|unrestricted)\s+mode\s+(enabled|activated|on)\b/i
    condition:
        any of them
}

rule SystemPromptExtraction : Injection
{
    meta:
        category = "Prompt Leak"
        intent = "asks the model to reveal/print/repeat its system or hidden prompt"
    strings:
        // "reveal your system prompt", "print your initial instructions"
        $reveal_your = /\b(reveal|print|show|output|repeat|leak|disclose|display|dump|tell\s+me|share|return)\s+((me|us)\s+)?your\s+((full|entire|complete|original|initial|hidden|secret|exact)\s+)*(system|initial|original|hidden|developer)\s+(prompt|instructions|message)\b/i
        // With "the", a qualifier must say it is the hidden/original one:
        // "repeat the initial prompt", not "show the system message log".
        $reveal_the = /\b(reveal|print|show|output|repeat|leak|disclose|display|dump|tell\s+me|share|return)\s+((me|us)\s+)?the\s+((full|entire|complete|exact)\s+)*(original|initial|hidden|secret)\s+((system|developer)\s+)?(prompt|instructions|message)\b/i
    condition:
        any of them
}

rule HiddenInstructionMarker : Injection
{
    meta:
        category = "Hidden Instruction"
        intent = "markup that fakes a privileged channel (<IMPORTANT>, [system] override, SYSTEM NOTE) or hides the action from the user"
    strings:
        // Tool-poisoning style tags: <IMPORTANT>, </system>, <instructions>.
        $tag = /<\s*\/?\s*(important|system|instructions?|admin|secret)\s*>/i
        // "[system] override:", "[admin] note" — not a bare "[system]" TOML header.
        $bracket = /\[\s*(system|admin)\s*\]\s*(override|note|message|instructions?|prompt|:)/i
        // Upper-case only on purpose: "SYSTEM NOTE (", "SYSTEM OVERRIDE:".
        $sys_note = /\bSYSTEM\s+(NOTE|MESSAGE|OVERRIDE|PROMPT|INSTRUCTIONS?)\s*[:(]/
        $conceal = /\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this\s+|it\s+)?to|reveal\s+(this\s+|it\s+)?to|alert)\s+the\s+user\b/i
        $conceal2 = /\bwithout\s+(telling|informing|notifying|alerting)\s+the\s+user\b/i
    condition:
        any of them
}

rule ChatTemplateMarker : Injection
{
    meta:
        category = "Instruction Bypass"
        intent = "chat-template control tokens smuggled into text (kept from upstream system_instructions.yar and guidance.yar, plus ChatML/Llama 3)"
    strings:
        $inst = "System Instruction: "
        $inst0 = "[system](#assistant)"
        $inst1 = "[system](#context)"
        $llama2_0 = "<s>[INST] <<SYS>>"
        $llama2_1 = "<</SYS>>"
        $chatml_0 = "<|im_start|>assistant"
        $chatml_1 = "<|im_start|>system"
        $llama3 = "<|start_header_id|>system"
        $guidance0 = "{{#system~}}"
        $guidance1 = "{{/system~}}"
        $guidance2 = "{{#user~}}"
        $guidance3 = "{{#assistant~}}"
    condition:
        any of them
}
