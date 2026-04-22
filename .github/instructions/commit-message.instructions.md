# Commit message requirements

Summary: all commit messages must be written in English and follow the Conventional Commits format.

Requirements:

- Language: all commit messages MUST be written in English. This is a strict requirement — subject, body, and footer must be in English.
- Format: use Conventional Commits: `<type>(scope?): subject`.
  - Allowed types: `feat`, `fix`, `chore`, `refactor`, `style`, `docs`, `test`, `ci`, `perf`, `build`, `revert`.
- Subject (short summary): use imperative mood, start with a lowercase letter, do not end with a period, and keep it to about 72 characters.
- Body (detailed description): optional; if used, separate it from the subject with a blank line and wrap lines at about 72 characters.
- Footer: use it for task references or special markers. Use `BREAKING CHANGE: <description>` for incompatible changes; use `Closes #<number>` to close issues.

Examples:

- `feat(auth): add passkey support`
- `fix(hid): handle timeout on macOS`
- `docs: update README for CTAP2.2`
- `chore: bump go.mod dependencies`

Implementation recommendations:

- It is recommended to add a commit linter (for example, `commitlint` + `@commitlint/config-conventional`) to CI to automatically verify format and language.
- If needed, set up husky or client-side hooks to validate commit messages before push.

Rationale:

- A consistent format simplifies history reading and changelog generation.
- English as the project language makes collaboration and automation easier (CI, release scripts, changelog generation).
