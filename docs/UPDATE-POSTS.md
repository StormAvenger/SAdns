# Update posts

Every public post about a change starts with the same three-line header, so anyone can tell at a glance what changed and whether they need to act. Technical detail goes below it, for the people who want it.

This applies to: release notes, changelog version entries, pull request descriptions, and issue replies that announce a fix or give a status update.

```markdown
**In short:** <one plain sentence>
**Type:** <label(s)>
**Should you update?** <answer>

---

<technical details, as usual>
```

## In short

- One sentence, two at most. Plain words. Say what changes for the user, not how the code works.
- It doesn't have to be a true ELI5. "Fixed a memory leak so it uses less memory over time." is right. Explaining what caused the leak is not; that goes below the line.
- Big or deep changes still get one sentence. The size of the change doesn't change the size of the summary.
- Several changes in one post: name the most important one, then "plus smaller fixes".

## Type

| Label | Meaning |
| --- | --- |
| 🔒 Security | Fixes a security risk |
| ⚠️ Breaking | You must change something (a setting, mapping or config) when you update |
| 🐛 Bug fix | Something that was broken now works |
| ✨ Feature | Something new you can use |
| ⚡ Performance | Faster or lighter, same behavior |
| 🧹 Maintenance | Dependencies, docs, CI or cleanup; nothing you'll notice |

If several apply, list them all in the order of this table, e.g. `🔒 Security · 🐛 Bug fix`.

## Should you update?

Use one of these:

- **Yes, now.** Security fixes, and bugs that lose data or break the main feature.
- **Yes, when convenient.**
- **Only if …** e.g. "Only if you use the camera."
- **No need.** Maintenance only.

For a ⚠️ Breaking change, add what to do: "Yes, but read the upgrade steps below first."
For an issue status reply before a fix ships: "Not yet. The fix is coming in vX.Y.Z."

## Security posts

- Keep the summary generic: "Fixed a security risk. Please update." For several at once: "Fixed several security risks. Please update."
- Don't explain the vulnerability or how to exploit it in the header. In the technical section, link the advisory or CVE instead of describing the attack, at least until users have had time to update.
- Security fixes are always **Yes, now.**

## Examples

```markdown
**In short:** Fixed several security risks. Please update.
**Type:** 🔒 Security
**Should you update?** Yes, now.
```

```markdown
**In short:** Fixed a memory leak so it uses less memory over long runs, plus smaller fixes.
**Type:** 🐛 Bug fix · ⚡ Performance
**Should you update?** Yes, when convenient.
```

```markdown
**In short:** Renamed two settings; your old values carry over, but automations that use them need the new names.
**Type:** ⚠️ Breaking · ✨ Feature
**Should you update?** Yes, but read the upgrade steps below first.
```

```markdown
**In short:** Updated build dependencies. Nothing changes for you.
**Type:** 🧹 Maintenance
**Should you update?** No need.
```

## In this repository

- Each version section in `CHANGELOG.md` starts with the header, right under the `## vX.Y.Z — date` line. The release workflow copies that section into the GitHub release, so the header appears there automatically.
