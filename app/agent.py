"""Tool-calling agent on Groq (OpenAI-compatible API, default model openai/gpt-oss-120b).
The LLM never sees raw data it invents: it can only call graph tools, and every answer carries a trace of the tool calls."""
import os, json, httpx

URL = "https://api.groq.com/openai/v1/chat/completions"
SYSTEM = ("You are BreachLens, a security analyst agent. You MUST call the graph tools to get evidence before answering. "
          "Use only tool output: never invent CVEs, assets, edges or scores. Say that graph reachability plus a known weakness is a candidate path, "
          "not proof of exploitability, and that the data is synthetic. Answer in under 150 words and name the specific fix and the paths that remain.")
def _t(name, desc, props=None):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props or {}, "required": list((props or {}).keys())}}}
def tools(actions):
    return [_t("find_attack_paths", "Run the FalkorDB traversal: all candidate attack paths from the Internet to sensitive data, with scores and findings."),
            _t("simulate_fix", "Simulate one remediation on an isolated copy of the graph and return removed and remaining paths.",
               {"action": {"type": "string", "enum": actions}}),
            _t("recommend_fixes", "Simulate every candidate fix and rank them by risk removed.")]

async def run_agent(question, impl, actions):
    key = os.getenv("GROQ_API_KEY")
    if not key: return None
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
    trace = []
    async with httpx.AsyncClient(timeout=60) as c:
        for _ in range(6):
            r = await c.post(URL, headers={"Authorization": f"Bearer {key}"},
                             json={"model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"), "messages": msgs,
                                   "tools": tools(actions), "tool_choice": "auto", "temperature": 0.2})
            r.raise_for_status()
            msg = r.json()["choices"][0]["message"]
            if not msg.get("tool_calls"):
                return {"answer": msg.get("content") or "", "trace": trace}
            msgs.append({"role": "assistant", "content": msg.get("content"), "tool_calls": msg["tool_calls"]})
            for tc in msg["tool_calls"]:
                name, args = tc["function"]["name"], json.loads(tc["function"]["arguments"] or "{}")
                try: out = impl[name](**args)
                except Exception as e: out = {"error": str(e)}
                trace.append({"tool": name, "args": args})
                msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": json.dumps(out)[:6000]})
    return {"answer": "Agent stopped after too many steps.", "trace": trace}
