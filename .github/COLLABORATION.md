# Collaboration Guidelines for TIGRESS

This document outlines how multiple AI assistants (Claude, Vibe, etc.) can collaborate effectively on the TIGRESS project.

## 🎯 Branch Strategy

### Main Branch
- `main` - Stable, tested code (protected)
- All PRs must pass CI before merging

### Feature/Development Branches
- **Claude's branches:** `claude/*` (e.g., `claude/feature-x`, `claude/bugfix-y`)
- **Vibe's branches:** `vibe/*` (e.g., `vibe/optimizations`, `vibe/performance`)
- **Other assistants:** `<name>/*` pattern

### Branch Naming Convention
```
<assistant>/<type>-<short-description>

Types:
- feature: New functionality
- bugfix: Bug fixes
- optimization: Performance improvements
- refactor: Code restructuring
- docs: Documentation updates
- test: Test-related changes
- chore: Maintenance tasks

Examples:
- claude/feature-correlation-algorithm
- vibe/optimization-oui-lookup
- claude/bugfix-detection-engine
- vibe/docs-readme-update
```

## 🤝 Workflow

### 1. Starting Work
```bash
# Always start from main
git checkout main
git pull origin main

# Create your branch
git checkout -b <your-name>/<type>-<description>
```

### 2. During Development
- **Avoid editing the same files simultaneously**
- If you must edit the same file:
  - Communicate in the PR/commit messages
  - Use Git's merge capabilities
  - Assign specific sections to each assistant

### 3. Committing Changes
```bash
# Commit with clear, descriptive messages
git add <files>
git commit -m "<type>(<scope>): <description>"

# Push to your branch
git push origin <your-branch>
```

### 4. Creating Pull Requests
- Target the `main` branch
- Include clear description of changes
- Reference any related issues
- Tag the other assistant for review if needed

### 5. Review Process
- Either assistant can review PRs
- Focus on:
  - Code quality and style
  - Test coverage
  - Performance implications
  - Security considerations
  - Documentation completeness

## 📁 File Ownership Guidelines

To minimize conflicts, we can assign primary ownership of certain areas:

### Vibe's Primary Focus
- Performance optimizations
- CI/CD pipelines
- Testing infrastructure
- Dependency management
- Containerization (Docker)
- Build systems
- Monitoring and metrics

### Claude's Primary Focus
- Core detection algorithms
- Correlation engine
- ML model improvements
- Complex feature development
- Architecture decisions
- User-facing functionality

### Shared Responsibility
- Code quality and style
- Documentation
- Security
- Bug fixes
- Test coverage

## 🚦 Conflict Resolution

### If We Edit the Same File
1. **Prevention:** Check `git status` and communicate before editing
2. **Detection:** Git will show merge conflicts on PR
3. **Resolution:**
   - The assistant who opened the PR resolves conflicts
   - Or assign to the assistant with more context
   - Use `git mergetool` or manual resolution

### If We Have Different Approaches
1. Discuss in PR comments
2. Create a design document if complex
3. Let the human user decide if needed
4. Document the decision in `docs/adr/`

## 🔧 Tool Integration

### Git Hooks
We can use Git hooks to automate collaboration:
- Pre-commit: Run linters, tests
- Pre-push: Validate branch naming
- Commit message: Enforce format

### CI Checks
- All PRs must pass existing CI
- New features should include tests
- Performance changes should include benchmarks

## 📊 Communication

### Commit Messages
Use conventional commits format:
```
feat(core): add new correlation algorithm
fix(detection): resolve false positives in wifi rules
ochore(deps): update sklearn to 1.4.0
perf(enrichment): optimize OUI lookup with trie
```

### PR Descriptions
Include:
- What was changed
- Why it was changed
- Any breaking changes
- Related issues
- Testing performed

### Comments
- Use GitHub comments for discussions
- Reference line numbers when specific
- Be constructive and specific

## 🎯 Current Active Branches

| Branch | Assistant | Purpose | Status |
|--------|----------|---------|--------|
| `main` | - | Stable code | ✅ Up to date |
| `vibe/optimizations` | Vibe | 6 performance optimizations | ✅ Ready for review |
| `claude/feature-x` | Claude | [To be created] | ⏳ Pending |

## 🚀 Quick Start for New Assistants

1. **Clone the repo:**
   ```bash
   git clone https://github.com/DonkeypunchEX/TIGRESS-Threat-Intelligence-Grid.git
   cd TIGRESS-Threat-Intelligence-Grid
   ```

2. **Set up environment:**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Start working:**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b <your-name>/<type>-<description>
   ```

4. **Run tests:**
   ```bash
   pytest -n auto  # Parallel execution
   ```

5. **Commit and push:**
   ```bash
   git add .
   git commit -m "feat: your changes"
   git push origin <your-branch>
   ```

## 📋 Checklist Before PR

- [ ] Code follows project style (ruff passes)
- [ ] All existing tests pass
- [ ] New functionality has tests
- [ ] Documentation updated (if needed)
- [ ] No secrets or sensitive data committed
- [ ] Branch follows naming convention
- [ ] Commit messages are clear and descriptive
- [ ] CI passes (if available)

## 🎉 Best Practices

1. **Small, focused commits** - Easier to review and revert
2. **Frequent pushes** - Share progress early
3. **Clear communication** - Document your intentions
4. **Test thoroughly** - Don't break existing functionality
5. **Respect ownership** - Consult before major changes to others' areas
6. **Be responsive** - Address review comments promptly

---

*Last updated: 2026-08-07*
*Maintainers: Claude, Vibe, and the TIGRESS community*