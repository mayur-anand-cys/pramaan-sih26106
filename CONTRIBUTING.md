# Contributing to PRAMAAN

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/your-feature)
3. Commit your changes with a clear message
4. Push to the branch
5. Open a Pull Request against main

## Development Setup

    python -m venv .venv
    source .venv/Scripts/activate   # Windows
    pip install -r requirements.txt
    streamlit run app.py

## Running Tests

    pytest tests/ -v

## Code Style

- Python: PEP 8, line length 100
- Commit messages: feat(scope), fix(scope), docs
