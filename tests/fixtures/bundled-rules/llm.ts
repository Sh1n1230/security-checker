// semgrep --test 用の fixture (src/security_checker/rules/semgrep/llm.yml)。実行はしない。
import OpenAI from "openai";
import got from "got";
import ky from "ky";
import * as undici from "undici";

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

export async function gotAsInstructions(url: string) {
  const response = await got(url);
  return client.responses.create({
    model: "m",
    // ruleid: llm-third-party-text-in-system-prompt-js
    instructions: response.body,
  });
}

export async function kyAsSystemPrompt(url: string) {
  const page = await ky.get(url).text();
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-system-prompt-js
      { role: "system", content: page },
    ],
  });
}

export async function undiciAsUserMessage(url: string) {
  const response = await undici.request(url);
  const page = await response.body.text();
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-user-message-js
      { role: "user", content: page },
    ],
  });
}

export async function trustedConstantWithThirdPartyClients() {
  // Merely importing the HTTP clients must not taint unrelated local text.
  const local = "Fixed internal instruction";
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ok: llm-third-party-text-in-system-prompt-js
      { role: "system", content: local },
    ],
  });
}

export async function statusOnly(url: string) {
  // 応答の本文ではない数値は、第三者のテキストではない (#281)
  const res = await fetch(url);
  const status = res.status;
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ok: llm-third-party-text-in-system-prompt-js
      { role: "system", content: `The last check returned ${status}.` },
      { role: "user", content: "Go." },
    ],
  });
}

export async function reviewCommentAsInstructions(octokit: any) {
  const comments = await octokit.rest.pulls.listReviewComments({ owner: "a", repo: "b", pull_number: 1 });
  const reviewBody = comments.data[0].body;
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-system-prompt-js
      { role: "system", content: reviewBody },
    ],
  });
}

export async function issueListingAsUserMessage(octokit: any) {
  const issues = await octokit.rest.issues.listForRepo({ owner: "a", repo: "b" });
  const issueBody = issues.data[0].body;
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-user-message-js
      { role: "user", content: issueBody },
    ],
  });
}

export async function graphqlCommentAsInstructions(octokit: any) {
  const result = await octokit.graphql("query { repository { issue { body } } }");
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ruleid: llm-third-party-text-in-system-prompt-js
      { role: "system", content: result.repository.issue.body },
    ],
  });
}

export async function constantWithOctokitPresent(octokit: any) {
  const count = 12;
  await octokit.rest.pulls.listReviewComments({ owner: "a", repo: "b", pull_number: 1 });
  return client.chat.completions.create({
    model: "m",
    messages: [
      // ok: llm-third-party-text-in-system-prompt-js
      { role: "system", content: `Processed ${count} items` },
    ],
  });
}
