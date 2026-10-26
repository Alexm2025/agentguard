# Framework integrations

## LangChain / LangGraph

```python
from agentguard.sdk.langchain import guard_tools, AgentGuardCallbackHandler

tools = guard_tools([search, send_email], guard)                 # works with ToolNode / create_react_agent
llm = ChatOpenAI(model="gpt-4.1", callbacks=[AgentGuardCallbackHandler(guard)])
```

The callback rebuilds provenance from the exact messages sent to the chat model on every call.

## LlamaIndex

```python
from agentguard.sdk.llamaindex import guard_tools

tools = guard_tools([FunctionTool.from_defaults(fn=send_email)], guard)
with guard.session(user=prompt):
    response = await agent.run(prompt)
```

LlamaIndex does not expose the raw model input to callbacks in a stable way, so open a
`guard.session(user=...)` with the user's request.

## OpenAI Agents SDK

```python
from agentguard.sdk.openai_agents import guard_agent, AgentGuardRunHooks

agent = guard_agent(agent, guard)                         # wraps FunctionTools, including handoffs
result = await Runner.run(agent, prompt, hooks=AgentGuardRunHooks(guard))
```

`AgentGuardRunHooks.on_llm_start` feeds the model's actual input items into the provenance ledger.
