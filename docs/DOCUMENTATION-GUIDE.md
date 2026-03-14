# Documentation Guide

This guide defines how documentation should be written in this repository.

## Main Principle

Write for learners who are new to SOC work, SIEM concepts, or Wazuh.

The best documentation in this repository should answer these questions quickly:
- What is this?
- Why does it matter?
- What does it look like in practice?
- What should the learner do next?

## Recommended Structure For A Theory Page

Use this order when possible:

1. Topic overview
2. Why it matters in a SOC
3. Simple example or scenario
4. Architecture or workflow diagram
5. Technical explanation
6. Key commands or configuration example
7. Common mistakes
8. Next step or related topic

## Recommended Structure For A Lab

Use this order when possible:

1. Lab goal
2. Prerequisites
3. Environment requirements
4. Step-by-step actions
5. Expected output or success check
6. Troubleshooting
7. Cleanup or next step

## Writing Style

- Prefer short paragraphs over large blocks of text
- Explain one concept at a time
- Use plain language before advanced terms
- Define specialized terms the first time they appear
- Keep the tone instructional and practical

## Examples

Good example pattern:
- Start with one concrete event such as a failed login, file modification, or IDS alert
- Show how Wazuh receives it
- Show how the alert is stored and viewed
- Explain what an analyst would do next

Avoid:
- long reference-style sections with no real scenario
- listing many tools without explaining the relationship between them
- jumping into advanced architecture before showing a simple single-node example

## Formatting Rules

- Use Markdown headings in a clear hierarchy
- Use fenced code blocks with a language label when possible
- Use tables only when they improve readability
- Use bullet lists for short, scannable points
- Use Mermaid diagrams for workflows and architecture when helpful

## Images And Diagrams

Images should support learning, not decorate the page only.

Good uses:
- dashboard screenshots
- architecture diagrams
- alert flow diagrams
- side-by-side comparison visuals

When adding an image:
- place it near the section it supports
- make the file name descriptive
- prefer repository-local assets under `Assets/images/`

## Version-Sensitive Content

If a command or workflow depends on a version:
- mention the version clearly
- avoid teaching outdated defaults as if they are current
- add a note when the ecosystem has changed

## Link Quality

Before submitting documentation changes:
- verify local links resolve to real files
- remove references to files that do not exist yet
- if content is planned but not created, call it planned instead of linking to it

## Documentation Review Checklist

- [ ] Beginner-friendly introduction exists
- [ ] One real scenario or example exists
- [ ] Steps are logically ordered
- [ ] Links are valid
- [ ] Diagrams or visuals are used where helpful
- [ ] Content matches the actual repository structure
- [ ] The next step for the learner is clear