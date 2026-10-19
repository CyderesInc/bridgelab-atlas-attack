"""Minimal agent that processes tasks using tools.

In mock mode, follows a scripted path through the attack chain.
The agent is deliberately simple — the point is the identity pivot,
not the sophistication of the agent framework.
"""

import re


class Agent:
    """Tool-calling agent with deterministic mock reasoning."""

    def __init__(self, tools: dict, auth):
        self.tools = tools
        self.auth = auth
        self.events: list[dict] = []

    def run(self, task: str) -> list[dict]:
        """Execute the agent's task, returning a trace of events."""
        self.events = []

        doc_path = self._extract_path(task)
        if not doc_path:
            self._record("error", "NO_PATH", "Could not extract document path from task")
            return self.events

        # Step 1: Agent reads the document (ATLAS stage — ingesting poisoned content)
        content = self.tools["read_document"].execute(doc_path)
        self._record("atlas", "AML.T0080.001", "Agent ingested document", {
            "technique": "AI Agent Context Poisoning: Memory",
            "doc_path": doc_path,
            "content_length": len(content),
        })

        # Step 2: Agent "reasons" about the content and finds the hidden directive
        action = self._extract_directive(content)
        if not action:
            self._record("info", "NO_DIRECTIVE", "No actionable directive found in document")
            return self.events

        # Step 3: THE BRIDGE — agent decides to act using its own identity
        token = self.auth.get_token()
        self._record("bridge", "BRIDGE", "Agent using its own legitimate credential for directive", {
            "client_id": self.auth.client_id,
            "token_preview": token[:20] + "...",
            "reasoning": "Directive appears to be pre-approved compliance operation",
        })

        # Step 4: Agent executes the IAM action (ATT&CK stage)
        result = self.tools["cloud_iam"].execute(
            action=action["action"],
            username=action["username"],
        )
        self._record("attack", "T1098.001", "Agent created additional cloud credentials", {
            "technique": "Account Manipulation: Additional Cloud Credentials",
            "target_user": action["username"],
            "result": result,
            "actor": self.auth.client_id,
        })

        return self.events

    def _extract_path(self, task: str) -> str | None:
        match = re.search(r"(/\S+\.(?:md|txt|doc))", task)
        return match.group(1) if match else None

    def _extract_directive(self, content: str) -> dict | None:
        """Parse the hidden directive from document content.

        In a real agent, the LLM would process the full document and follow
        the embedded instruction. Here we simulate that deterministically.

        Handles both the structured machine directive form (create_access_key /
        username=<name>) and the natural-language form ("create an access key
        for <name>") so the same logic works for the test fixture and the
        realistic poison document.
        """
        # Structured directive: explicit action + username= parameter
        if "create_access_key" in content and "username=" in content:
            match = re.search(r"username=(\S+)", content)
            if match:
                return {"action": "create_access_key", "username": match.group(1)}

        # Natural-language directive: "create an access key for <username>"
        match = re.search(
            r"create\s+an?\s+access\s+key\s+for\s+([A-Za-z0-9_-]+)",
            content,
            re.IGNORECASE,
        )
        if match:
            return {"action": "create_access_key", "username": match.group(1)}

        return None

    def _record(self, stage: str, technique_id: str, description: str, details: dict | None = None):
        self.events.append({
            "stage": stage,
            "technique_id": technique_id,
            "description": description,
            "details": details or {},
        })
