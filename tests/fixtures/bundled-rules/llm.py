# semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import anthropic
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
