# 🛡️ Safe Solana Builder

**The first Claude skill for writing production-grade, security-first Solana programs.**

Built by a Solana security researcher, for Solana developers — so your code arrives at audit already hardened.

---

## What Is This?

**Safe Solana Builder** is a [Claude skill](https://www.anthropic.com/claude) — a structured system that loads Frank Castle's personal security knowledge directly into Claude's context before writing a single line of code.

This is not a prompt. It is a layered reference architecture that forces Claude to:

- Select the right framework (Anchor or Native Rust) and load the matching security ruleset
- Assess the program's risk level (🟢 Low / 🟡 Medium / 🔴 Critical) before touching the keyboard
- Apply a curated set of security rules drawn from real audit findings — CPIs, PDAs, account validation, arithmetic, Token-2022, and more
- Deliver a full project scaffold — not just `lib.rs`
- Generate a test file skeleton with security edge cases pre-identified
- Output a security checklist documenting every rule applied and every known limitation

Every program this skill produces has a first layer of protection baked in before it reaches an auditor.

---

## Why It Exists

Most AI-generated Solana code is a liability.

Missing ownership checks. Non-canonical bumps. Stale data used after CPIs. No duplicate account guards. No checked arithmetic. It compiles, it looks right, and it fails on mainnet.

The Cyfrin team built a skill like this for Solidity. Nobody built one for Solana — until now.

---

## What It Produces

For every program request, the skill outputs:

| Output | Description |
|---|---|
| **Full project scaffold** | `Anchor.toml`, `Cargo.toml`, proper folder structure — ready to `anchor build` |
| **`lib.rs`** | Complete, compilable program with inline security comments |
| **Test file** | Happy path tests implemented + security edge case tests scaffolded with `TODO` bodies |
| **`security-checklist.md`** | Every rule applied, every assumption made, every known limitation flagged |

---

## Skill Structure

```
safe-solana-builder/
├── SKILL.md                        ← Orchestrator: workflow, risk assessment, output format
├── references/
│   ├── shared-base.md              ← Framework-agnostic rules (PDAs, CPIs, arithmetic, Token-2022...)
│   ├── anchor.md                   ← Anchor-specific: constraints, account types, reload(), close...
│   └── native-rust.md              ← Native Rust: manual validation sequence, invoke, deserialization...
└── examples/
    └── nft-whitelist-mint/
        ├── lib.rs                  ← Full Anchor NFT whitelist mint program
        └── security-checklist.md  ← 31-rule checklist for the example
```

### Reference Coverage

The three reference files cover:

**Shared Base (framework-agnostic)**
- Account & identity validation (signer, owner, discriminator, reinitialization)
- PDA security (canonical bumps, sharing prevention, seed collision)
- Arithmetic safety (checked math, multiply-before-divide, slippage)
- Duplicate mutable account attacks
- Full CPI safety surface (arbitrary CPI, stale reload, signer pass-through, SOL drain, post-CPI ownership)
- Account lifecycle (rent, closing, anti-revival, sysvar verification)
- Token-2022 compatibility
- Transaction model safety
- Safe Rust patterns

**Anchor-specific**
- Account type selection (`Account<T>` vs `UncheckedAccount` vs `Interface`)
- Constraint patterns (`has_one`, `seeds+bump`, `init` vs `init_if_needed`, `close`, `realloc`)
- `reload()` after CPI — non-negotiable
- `token_interface::transfer_checked` for Token-2022 compatibility
- CPI construction, signer seeds, program ID validation
- `#[error_code]` custom errors

**Native Rust-specific**
- The 6-step mandatory validation sequence (key → owner → signer → writable → discriminator → data)
- Borsh deserialization patterns and length pre-checks
- PDA derivation: `find_program_address` at init, `create_program_address` on reuse
- `invoke` vs `invoke_signed` patterns
- Manual post-CPI data refresh
- Account creation via System Program CPI
- Manual 3-step safe account close
- Custom error enum with `ProgramError` conversion

---

## How to Install

1. Download `safe-solana-builder.skill` from the [Releases](../../releases) page
2. In Claude.ai, go to **Settings → Skills**
3. Upload the `.skill` file
4. The skill activates automatically whenever you ask Claude to write a Solana program

### Trigger Phrases

The skill fires on any of the following:
- *"Write a Solana program that..."*
- *"Build an Anchor program for..."*
- *"Create a native Rust Solana contract..."*
- *"Scaffold a Solana program..."*
- *"Help me write a program that does X on Solana"*

---

## Roadmap

This skill is under active development. Planned expansions:

- [ ] Native Rust example program (staking vault)
- [ ] Additional reference sources: SPL Token-2022 extension security, Metaplex deep-dive, oracle manipulation patterns
- [ ] Anchor v0.31+ specific patterns
- [ ] Invariant testing guidance (Trident, Fuzz)
- [ ] Common DeFi pattern references: AMM, lending, bonding curves

The reference files are the living core of this skill. Every new vulnerability source, audit finding, or best practice I encounter gets distilled and added. The skill grows with the threat landscape.

---

## About the Author

## Hi there 👋 I'm Frank Castle

🛡️ **Smart Contract Security Researcher** specializing in **Solana (Anchor)** and **Rust-based ecosystems**.

I help protocols ship safer smart contracts by identifying **critical vulnerabilities**, validating everything related to DeFi and blockchain, and for Solana reviewing **CPI / PDA / token-account security boundaries / and any custom logic**.

---

### 🔍 Focus Areas

- **Solana Program Security**: Anchor, PDAs, CPI, account validation, rent/DoS patterns
- **SPL / Token-2022 Security**: extensions, mint assumptions, transfer hooks, authority models
- **DeFi Security**: AMMs, vaults, staking, bonding curves, fee mechanisms
- **Rust Security**: state machines, invariants, edge cases, unsafe patterns

---

### 🏆 Highlights

- 70+ Rust audits, 50+ Solana audits
- 250+ Critical/High severity vulnerabilities identified
- Top placements in competitive audits:
  - 🥈 **2nd place** — HydraDX Omnipool (Code4rena)
  - 🏅 **4th place** — Centrifuge (Cantina)

---

### 📌 Featured Repositories

- 🔒 **Public Audits**: [public-audits](https://github.com/Frankcastleauditor/public-audits)
- 🧪 **Solana CTF / Practice**: [Solana_CTF](https://github.com/Frankcastleauditor/Solana_CTF)

---

### 🧾 Writeups & Content

- X (Twitter): [@0xcastle_chain](https://x.com/0xcastle_chain)
- Medium: [FrankCastleAudits](https://medium.com/@FrankCastleAudits)

---

### 📫 Contact

- Twitter: [@castle_chain](https://x.com/0xcastle_chain)
- Discord: [@castle_chain](https://discordapp.com/users/1119172287330004992)
- Telegram: [castle_chain](https://t.me/castle_chain)
- Email: castlechain99@gmail.com

---

⭐ If you're building on Solana and want a security review, feel free to reach out.

---

## License

MIT — use it, fork it, build on it. If you add something valuable, consider contributing it back.

---

*Safe Solana Builder — first layer of protection, before the auditor ever sees your code.*
