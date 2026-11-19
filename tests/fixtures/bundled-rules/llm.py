# semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import anthropic
import ollama
import openai
import requests
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
