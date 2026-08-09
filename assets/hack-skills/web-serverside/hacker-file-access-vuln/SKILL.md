---
name: hacker-file-access-vuln
description: "Entry P1 category router for file access and upload workflows. Use when testing download endpoints, file paths, local file inclusion, upload flows, preview pipelines, archive extraction, or storage and sharing boundaries."
metadata:
  hermes:
    tags: [web-serverside, "redteam", "offensive"]
    related_skills: ["hacker-401-403-bypass-techniques", "hacker-arbitrary-write-to-rce", "hacker-business-logic-vuln", "hacker-business-logic-vulnerabilities", "hacker-dependency-confusion", "hacker-file-access-vuln", "hacker-graphql-and-hidden-parameters", "hacker-http-host-header-attacks", "hacker-http2-specific-attacks", "hacker-path-traversal-lfi", "hacker-race-condition", "hacker-request-smuggling", "hacker-upload-insecure-files", "hacker-waf-bypass-techniques", "hacker-web-cache-deception", "hacker-cmdi-command-injection"]
---


# File Access Router

This is the routing entry point for filesystem paths, download endpoints, upload pipelines, and file preview handling.

## When to Use

- Parameters, filenames, download endpoints, or import flows influence file paths
- The target supports upload, preview, transcoding, extraction, sharing, download, or proxied file access
- You need to decide whether this is path traversal/LFI or an upload-validation/processing-chain issue

## Skill Map

- [Path Traversal LFI](../path-traversal-lfi/SKILL.md): path traversal, file read, wrapper abuse, include chains
- [Upload Insecure Files](../upload-insecure-files/SKILL.md): upload validation, storage paths, processing chains, overwrite risk, preview/share boundaries

## Recommended Flow

1. First identify whether the entry point is a path parameter, download endpoint, or upload workflow
2. Then locate whether the issue appears in accept, store, process, or serve stages
3. Small path-chain and upload-bypass samples are merged into the main topic skills; no separate payload entry is needed

## Related Categories

- [injection-checking](../injection-checking/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)