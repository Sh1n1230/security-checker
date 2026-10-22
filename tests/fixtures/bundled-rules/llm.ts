// semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import OpenAI from "openai";

const client = new OpenAI();

export async function summarize(url: string) {
  const res = await fetch(url);
  const page = await res.text();
  return client.chat.completions.create({
    model: "m",
    messages: [
      { role: "system", content: "Summarize the page." },
      // ruleid: llm-third-party-text-in-user-message-js
      { role: "user", content: `Page:\n${page}` },
    ],
  });
}

export async function pageAsInstructions(url: string) {
  const page = await fetch(url).then((r) => r.text());
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-system-prompt-js
      { role: "system", content: page },
      { role: "user", content: "Go." },
    ],
  });
}

export async function constantsOnly() {
  const question = "What is 2 + 2?";
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ok: llm-third-party-text-in-user-message-js
      { role: "user", content: question },
    ],
  });
}
