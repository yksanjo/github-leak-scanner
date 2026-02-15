# GitHub Leak Scanner

A CLI tool that monitors GitHub repositories, gists, and commits for leaked credentials from your domains.

## Installation

```bash
cd github-leak-scanner
npm install
```

## Usage

### Basic Usage

```bash
# Single scan
node src/index.js -d example.com -o

# With GitHub token (recommended for higher rate limits)
node src/index.js -d example.com -t YOUR_GITHUB_TOKEN

# Continuous monitoring
node src/index.js -d example.com,yourcompany.com
```

### With Configuration File

Create a `config.json` file:

```json
{
  "domains": ["example.com", "yourcompany.com"],
  "githubToken": "your_github_token_here",
  "interval": 30,
  "verbose": false
}
```

Then run:

```bash
node src/index.js
```

## Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config` | `-c` | Path to config file | `config.json` |
| `--domains` | `-d` | Comma-separated list of domains | (required) |
| `--token` | `-t` | GitHub personal access token | env.GITHUB_TOKEN |
| `--once` | `-o` | Run once and exit | Continuous |
| `--interval` | `-i` | Check interval in minutes | 30 |
| `--verbose` | `-v` | Verbose output | false |

## Features

- Searches GitHub code for leaked credentials
- Monitors public gists for credentials
- Supports GitHub API with authentication
- Detects multiple credential types

## License

MIT
