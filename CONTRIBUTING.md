# Contributing to JWT Analyzer

## Development Environment Setup

### Prerequisites
- [GHCup](https://www.haskell.org/ghcup/) for managing Haskell toolchain
- GHC 8.10.7 or later
- Cabal 3.4 or later
- HLS (Haskell Language Server)
- HLint

### Setting up the development environment

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/jwt-analyzer.git
   cd jwt-analyzer
   ```

2. Install dependencies:
   ```
   cabal update
   cabal build --only-dependencies --enable-tests
   ```

3. Build the project:
   ```
   cabal build
   ```

4. Run the tests:
   ```
   cabal test
   ```

5. Run HLint to check code quality:
   ```
   hlint src app test
   ```

### Editor Setup

#### VSCode
1. Install the Haskell extension for VSCode
2. Open the project folder in VSCode
3. The Haskell Language Server should start automatically

#### Emacs
1. Install haskell-mode and lsp-mode
2. Configure lsp-mode to use HLS

#### Vim/Neovim
1. Install a Haskell plugin (like haskell-vim)
2. Configure LSP client to use HLS

## Development Workflow

1. Create a new branch for your feature
2. Implement your changes
3. Add tests for your functionality
4. Ensure all tests pass
5. Run HLint and fix any issues
6. Submit a pull request
