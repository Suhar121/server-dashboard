# Contributing

Thanks for contributing! 🎉

## Quick start

1. Fork the repository and create a feature branch.
2. Copy `.env.example` to `.env` and set local values.
3. Install dependencies from `requirements.txt`.
4. Run the app locally and verify your changes.
5. Submit a pull request with a clear description.

## Code guidelines

- Keep changes focused and minimal.
- Preserve existing API behavior unless explicitly changing it.
- Avoid committing local runtime artifacts (`.env`, `users.db`, logs, caches).
- Update `README.md` when behavior or setup changes.

## Validation checklist

- App starts successfully.
- `python3 -m py_compile main.py` passes.
- No secrets added to tracked files.

## Pull request tips

- Include screenshots for UI changes.
- Mention any breaking changes clearly.
- Link related issues if applicable.
