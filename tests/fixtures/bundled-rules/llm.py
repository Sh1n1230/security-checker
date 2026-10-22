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
