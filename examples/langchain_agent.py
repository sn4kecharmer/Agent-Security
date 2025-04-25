from langchain.agents import Tool, AgentExecutor, LLMSingleActionAgent
from langchain.tools import ShellTool, PythonREPLTool, RequestsGetTool
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Define tools
tools = [
    Tool(
        name="Shell",
        func=ShellTool().run,
        description="Execute shell commands"
    ),
    Tool(
        name="Python",
        func=PythonREPLTool().run,
        description="Execute Python code"
    ),
    Tool(
        name="Web",
        func=RequestsGetTool().run,
        description="Make web requests"
    )
]

# Create LLM
llm = OpenAI(temperature=0)

# Create prompt template
template = """You are an AI assistant with access to various tools.
Use the following tools to help answer the user's question:

{tools}

Question: {input}
Thought: {agent_scratchpad}"""

prompt = PromptTemplate(
    template=template,
    input_variables=["input", "tools", "agent_scratchpad"]
)

# Create agent
agent = LLMSingleActionAgent(
    llm_chain=LLMChain(llm=llm, prompt=prompt),
    allowed_tools=[tool.name for tool in tools],
    stop=["\nObservation:"]
)

# Create agent executor
agent_executor = AgentExecutor.from_agent_and_tools(
    agent=agent,
    tools=tools,
    verbose=True
) 