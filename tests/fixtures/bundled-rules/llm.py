# semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import anthropic
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
