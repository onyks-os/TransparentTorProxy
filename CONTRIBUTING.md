# Contributing to TTP

First off, thank you for considering contributing to TTP! It's people like you who make TTP such a great tool for the privacy community.

## 📜 Code of Conduct

By participating in this project, you agree to maintain a professional and respectful environment. Please be kind to others.

## 🐛 How to Report Bugs

- **Check existing issues**: Someone might have already reported it.
- **Use the template**: Provide as much detail as possible.
- **Diagnostics**: Always include the output of `sudo ttp diagnose` if the bug is related to connectivity or system configuration.

## 💡 How to Propose Features

- Open an issue titled `[Feature Request] Your idea`.
- Explain why this feature is needed and how it fits the project's goal of simplicity and crash-safety.

## 🛠️ Development Setup

1. **Clone the repo**:

   ```bash
   git clone https://github.com/onyks-os/TransparentTorProxy.git
   cd TransparentTorProxy
   ```

2. **Create a virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install in editable mode with dev dependencies**:

   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests**:

   ```bash
   pytest tests/ -v
   ```

## 🏗️ Architectural Principles

When writing code for TTP, please adhere to these core principles:

1. **Single Responsibility Principle (SRP)**: Each module should do one thing. Keep UI logic (`rich`/`typer`) in `cli.py` and system logic in dedicated modules.
2. **No UI Coupling**: Modules like `tor_control.py` or `firewall.py` should NOT import `rich` or `typer`. Use callbacks or return raw data.
3. **Atomic Operations**: System changes (like firewall rules) must be atomic. We use `nft -f` to ensure the firewall is never in a half-configured state.
4. **Crash-Safety**: Always consider what happens if the power goes out mid-operation. Use the lock file system in `state.py` to track changes that need rolling back.
5. **TDD (Test Driven Development)**: Every new feature or bug fix should include a corresponding unit test in `tests/`.

## 🧪 Testing

- **Unit Tests**: Must pass on every PR. They are fully mocked and run without root.
- **Integration Tests**: Should be run in a VM (see `README.md`) to verify actual network behavior.

## 🚀 Pull Request Process

1. Create a branch from `main`.
2. Ensure all tests pass.
3. Update the documentation (`README.md`, `TDD.md`) if needed.
4. Submit the PR and wait for review.

Thank you for your help! 🛡️
