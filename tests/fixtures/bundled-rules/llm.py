# semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import anthropic
import ollama
import openai
import requests
import httpx
from bs4 import BeautifulSoup
from github import Github

client = openai.OpenAI()
claude = anthropic.Anthropic()


def summarize_page(url):
    page = requests.get(url, timeout=10).text
    return client.chat.completions.create(
        model="m",
        messages=[
            {"role": "system", "content": "Summarize the page."},
            # ruleid: llm-third-party-text-in-user-message
            {"role": "user", "content": f"Page:\n{page}"},
        ],
    )


def page_as_instructions(url):
    page = BeautifulSoup(requests.get(url, timeout=10).text, "html.parser").get_text()
    return client.chat.completions.create(
        model="m",
        messages=[
            # ruleid: llm-third-party-text-in-system-prompt
            {"role": "system", "content": page},
            {"role": "user", "content": "Go."},
        ],
    )


def triage_issue(token, number):
    issue = Github(token).get_repo("o/r").get_issue(number)
    return claude.messages.create(
        model="m",
        max_tokens=100,
        # ruleid: llm-third-party-text-in-system-prompt
        system="Triage this issue: " + issue.body,
        messages=[{"role": "user", "content": "Label it."}],
    )


def responses_api(url):
    body = requests.get(url, timeout=10).json()
    # ruleid: llm-third-party-text-in-user-message
    return client.responses.create(model="m", input=body["text"])


def requests_session_source(url):
    session = requests.Session()
    page = session.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-system-prompt
    return claude.messages.create(model="m", max_tokens=100, system=page, messages=[])


def requests_session_context(url):
    with requests.Session() as session:
        body = session.post(url, data={"q": "test"}).text
        # ruleid: llm-third-party-text-in-user-message
        return client.responses.create(model="m", input=body)


def httpx_client_source(url):
    transport = httpx.Client()
    page = transport.get(url).json()["text"]
    # ruleid: llm-third-party-text-in-system-prompt
    return claude.messages.create(model="m", max_tokens=100, system=page, messages=[])


async def httpx_async_client_context(url):
    async with httpx.AsyncClient() as transport:
        page = (await transport.get(url)).text
        # ruleid: llm-third-party-text-in-user-message
        return client.responses.create(model="m", input=page)


def unrelated_get_is_not_an_http_source(url, cache):
    session = requests.Session()
    page = cache.get(url)
    # ok: llm-third-party-text-in-system-prompt
    return claude.messages.create(model="m", max_tokens=100, system=page, messages=[])


def session_status_is_not_untrusted_text(url):
    session = requests.Session()
    status = session.get(url).status_code
    # ok: llm-third-party-text-in-system-prompt
    return claude.messages.create(model="m", max_tokens=100, system=f"status: {status}", messages=[])


def constants_only():
    question = "What is 2 + 2?"
    return client.chat.completions.create(
        model="m",
        messages=[
            # ok: llm-third-party-text-in-system-prompt
            {"role": "system", "content": "You are a calculator."},
            # ok: llm-third-party-text-in-user-message
            {"role": "user", "content": question},
        ],
    )


def status_only(url):
    # 応答の本文ではない数値・真偽値は、第三者のテキストではない (#281)
    code = requests.get(url, timeout=10).status_code
    return client.chat.completions.create(
        model="m",
        messages=[
            # ok: llm-third-party-text-in-system-prompt
            {"role": "system", "content": f"The last check returned {code}."},
            {"role": "user", "content": "Go."},
        ],
    )


def unrelated_invoke(url, my_task_runner, retriever, output_parser):
    # invoke という名前のメソッドは LLM に限らない (#282)
    page = requests.get(url, timeout=10).text
    # ok: llm-third-party-text-in-user-message
    my_task_runner.invoke(page)
    # ok: llm-third-party-text-in-user-message
    output_parser.invoke(page)
    # ok: llm-third-party-text-in-user-message
    return retriever.invoke(page)


def langchain_invoke(url, llm, chat_model, gpt, pipeline):
    page = requests.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-user-message
    llm.invoke(page)
    # ruleid: llm-third-party-text-in-user-message
    chat_model.invoke(page)
    # LLM らしくない名前でも、LLM でないと分かる名前でなければ見る
    # ruleid: llm-third-party-text-in-user-message
    gpt.invoke(page)
    # ruleid: llm-third-party-text-in-user-message
    return pipeline.invoke(page)


def ollama_system_prompt(url):
    page = requests.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-system-prompt
    return ollama.generate(model="m", prompt="Summarize the page", system=page)


def ollama_user_prompt(url):
    page = requests.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-user-message
    return ollama.generate(model="m", prompt=page, system="You are a helpful assistant")


def ollama_constant_prompts():
    # ok: llm-third-party-text-in-system-prompt
    # ok: llm-third-party-text-in-user-message
    return ollama.generate(model="m", prompt="Two plus two?", system="Answer clearly")


def ollama_response_status_is_not_prompt_injection(url):
    code = requests.get(url, timeout=10).status_code
    # ok: llm-third-party-text-in-user-message
    return ollama.generate(model="m", prompt=f"HTTP status: {code}")


def langchain_system_message(url):
    text = requests.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-system-prompt
    return SystemMessage(content=text)


def langchain_system_template(url):
    page = requests.get(url, timeout=10).text
    return ChatPromptTemplate.from_messages([
        # ruleid: llm-third-party-text-in-system-prompt
        ("system", page),
        ("human", "Summarize the document"),
    ])


def langchain_human_message(url):
    page = requests.get(url, timeout=10).text
    # ruleid: llm-third-party-text-in-user-message
    return HumanMessage(content=page)


def langchain_user_template(url):
    page = requests.get(url, timeout=10).text
    return ChatPromptTemplate.from_messages([
        ("system", "Be concise"),
        # ruleid: llm-third-party-text-in-user-message
        ("human", page),
    ])


def langchain_constant_templates():
    # ok: llm-third-party-text-in-system-prompt
    system = SystemMessage(content="You are helpful")
    # ok: llm-third-party-text-in-user-message
    human = HumanMessage(content="Hello")
    return ChatPromptTemplate.from_messages([
        # ok: llm-third-party-text-in-system-prompt
        ("system", "You are helpful"),
        # ok: llm-third-party-text-in-user-message
        ("human", "Hello"),
    ])


def bedrock_converse_system(url, bedrock_runtime):
    third_party_text = requests.get(url, timeout=10).text
    return bedrock_runtime.converse(
        modelId="model-id",
        # ruleid: llm-third-party-text-in-system-prompt
        system=[{"text": third_party_text}],
        messages=[{"role": "user", "content": [{"text": "Hello"}]}],
    )


def bedrock_converse_user(url, bedrock_runtime):
    third_party_text = requests.get(url, timeout=10).text
    return bedrock_runtime.converse(
        modelId="model-id",
        system=[{"text": "You are helpful."}],
        # ruleid: llm-third-party-text-in-user-message
        messages=[{"role": "user", "content": [{"text": third_party_text}]}],
    )


def bedrock_converse_static(bedrock_runtime):
    return bedrock_runtime.converse(
        modelId="model-id",
        # ok: llm-third-party-text-in-system-prompt
        system=[{"text": "Be concise."}],
        # ok: llm-third-party-text-in-user-message
        messages=[{"role": "user", "content": [{"text": "Hello"}]}],
    )


def bedrock_converse_non_text(url, bedrock_runtime):
    status = requests.get(url, timeout=10).status_code
    return bedrock_runtime.converse(
        modelId="model-id",
        # ok: llm-third-party-text-in-system-prompt
        system=[{"text": f"Previous HTTP status: {status}"}],
        messages=[{"role": "user", "content": [{"text": "Hello"}]}],
    )
