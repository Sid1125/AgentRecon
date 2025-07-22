from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

@tool
def say_hi() -> str:
    """Say hello from AgentRecon."""
    return "Hello from AgentRecon!"

tools = [say_hi]
llm = ChatOllama(model="mistral-nemo")  # <- must be a ChatModel

agent = create_react_agent(llm, tools)

while True:
    query = input("User: ")
    if query.lower() in ["exit", "quit"]:
        break
    result = agent.invoke({"messages": [{"role": "user", "content": query}]})
    print("Agent:", result["messages"][-1].content)

def test_context_target_memory(monkeypatch):
    """Test that the agent remembers the last used target if omitted in follow-up commands."""
    from langchain_agent import agent_runner
    # Reset context
    agent_runner.last_used_target = None
    calls = []
    # Patch tool invocation to record params
    def fake_invoke(params):
        calls.append(params)
        return f"Fake output for {params['target']}"
    # Patch tool map
    class FakeTool:
        def invoke(self, params):
            return fake_invoke(params)
    monkeypatch.setattr(agent_runner, 'load_registered_tools', lambda: [type('T', (), {'name': 'run_nmap', 'invoke': fake_invoke}), type('T', (), {'name': 'run_rustscan', 'invoke': fake_invoke})])
    monkeypatch.setattr(agent_runner, 'match_tool', lambda prompt: 'run_nmap' if 'nmap' in prompt else 'run_rustscan')
    # First prompt with explicit target
    out1 = agent_runner.run_prompt('run nmap on s.amizone.net')
    # Second prompt omits target
    out2 = agent_runner.run_prompt('now run rustscan')
    assert calls[0]['target'] == 's.amizone.net'
    assert calls[1]['target'] == 's.amizone.net'
    print('Context memory test passed.')
