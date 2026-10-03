# Jules Integration Rules

## Repo type
This is a **Python 3.11 / Streamlit / FastAPI** repository. NOT TypeScript.
Do NOT suggest npm, pnpm, vitest, ESLint, Prettier, or Tailwind.

## Correct commands for this repo
- Run tests: `python -m pytest tests/ -q`
- Syntax check: `python -c "import ast; ast.parse(open('FILE.py', encoding='utf-8').read())"`
- Run app: `streamlit run app.py`
- Lint: none (no linter configured)
- Format: none

## Rules
1. **ALWAYS branch from the latest `main`.** Run `git fetch origin && git checkout -B <branch> origin/main` before any edits.
2. **NEVER delete lines** unless the task explicitly says "remove X". If a diff exceeds 30 additions/deletions, stop and ask.
3. **One file per PR.** No multi-file refactors.
4. **Never touch**: `api.py`, `zkfv.py`, `backend/auth/`, `blockchain/`, `soc/`, `frontend/`, `.github/`. Those are CODEOWNERS-locked.
5. **Small scope only.** If a task feels big, decline and open an issue instead.
6. **Match the existing code style.** No new dependencies without updating `requirements.txt`.

## Where Jules can help (safe tasks)
- Writing tests in `tests/` for existing modules
- Adding type hints to small functions
- Generating docstrings for documented code
- Fixing specific, well-defined bugs (with a reproducer)
- Writing `docs/*.md` documentation

## Where Jules should NOT go (unsafe tasks)
- Refactoring `app.py` (it's the dashboard — 1,100+ lines, easy to break)
- UI redesigns (visual judgment required)
- Anything in the frontend SOC epic (#72–#81)
- "Improve" / "clean up" / "modernize" tasks without specific criteria
