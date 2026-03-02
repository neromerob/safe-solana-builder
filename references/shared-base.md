# Shared Base — Solana Security Rules & Best Practices
# Frank Castle — Safe Solana Builder
# Applies to ALL Solana programs regardless of framework (Native Rust or Anchor).
# Claude: read every line of this file before writing any program code.

---

## 1. ACCOUNT & IDENTITY VALIDATION

These are the most exploited categories in Solana. Every account that enters your program is untrusted by default.

### 1.1 Signer Checks
- **Always verify `is_signer`** on every account that must authorize an action. An account being present in the accounts list does NOT mean it signed.
- Never treat account presence as authorization. Solana passes all accounts in a flat list — position alone means nothing.
- For authority-based operations (admin actions, user mutations), `is_signer` must be checked explicitly, every time.

### 1.2 Ownership Checks
- **Always verify `account.owner == expected_program_id`** before reading or trusting any account's data.
- An attacker can craft an account with identical data layout owned by a malicious program. If you skip the owner check, you'll read and act on spoofed data.
- The system program, token program, and your own program each have different owner IDs — never conflate them.

### 1.3 Account Data Matching (has_one / constraints)
- Validate that related accounts actually belong together. A user's vault PDA must match the pubkey stored in the user's state account — not just be a valid vault.
- Use `has_one` (Anchor) or manual pubkey comparison (native) to enforce these cross-account relationships.
- Example failure: accepting any token account for a "user's" withdrawal, not just the one registered to that user.

### 1.4 Type Cosplay Prevention (Discriminators)
- Every account type must have a unique **discriminator** (first 8 bytes in Anchor; manually managed in native).
- An attacker can pass an `Admin` account where a `User` account is expected if you don't check the discriminator.
- Always deserialize into the specific expected type and validate its discriminant before trusting any fields.

### 1.5 Reinitialization Attacks
- **Verify an account has not already been initialized before running setup logic.**
- If `initialize` can be called twice, an attacker can overwrite the authority field and hijack the program.
- Use a dedicated `initialized: bool` flag, or rely on Anchor's `init` constraint which prevents reinit by checking account discriminator and ownership.

### 1.6 Writable Checks
- Only accounts explicitly marked as writable (`is_writable`) should be modified.
- Never modify an account not marked writable — doing so will cause a runtime error at best, and a silent corruption at worst in earlier runtime versions.
- `is_signer` and `is_writable` are per-transaction, not per-instruction. Never assume they differ across instructions in the same transaction.

---

## 2. PDA (PROGRAM DERIVED ADDRESSES) SECURITY

PDAs are the backbone of Solana state. A poorly designed PDA is a permanently exploitable backdoor.

### 2.1 Canonical Bumps Only
- **Always use `find_program_address`** to find the canonical (highest valid) bump.
- Never allow a user to supply an arbitrary bump seed. An attacker can pre-mine a bump that results in the same address as another account.
- **Store the canonical bump** in the account's data after creation and **reuse it** on subsequent calls — never brute-force it again on every invocation.
- Use `create_program_address` (with the stored bump) for re-derivation, not `find_program_address`, to save compute.

### 2.2 PDA Sharing Prevention
- Seeds must be specific enough that one PDA can never serve two different users or purposes.
- **Always include the user's `Pubkey` in seeds** for any user-specific state. Example: `[b"vault", user.key().as_ref()]`.
- A shared PDA means one user can affect another's state — this is a critical vulnerability.

### 2.3 Seed Collision Prevention
- Use **unique string prefixes** for different PDA types: `b"vault"`, `b"user_state"`, `b"config"`, etc.
- Seeds `["AB", "C"]` and `["A", "BC"]` produce the **same PDA** — this is a known footgun with concatenated seeds.
- Always use fixed-length seeds or canonical delimiters when seed components come from user input.
- Never assume a PDA derived from user-provided seeds is unique unless you fully control and validate the seed composition.

### 2.4 PDA Purpose Isolation
- Never use a single PDA across multiple logical domains or external programs.
- Each distinct capability (vault, escrow, config, staking position) must use a distinct PDA with distinct seeds.

---

## 3. ARITHMETIC & LOGIC SAFETY

A single overflow or division-before-multiplication can drain a protocol.

### 3.1 Checked / Saturating Math — No Exceptions
- **Never use standard `+`, `-`, `*` operators on financial values.** They will panic (debug) or silently overflow (release).
- Use `.checked_add()`, `.checked_sub()`, `.checked_mul()`, `.checked_div()` and propagate errors with `?`.
- Use `.saturating_sub()` only when a floor of zero is semantically correct (e.g., health factors).
- Treat every arithmetic error as a program bug, not a user error — return a descriptive custom error.

### 3.2 Multiply Before Divide
- **Always perform all multiplications first, then divide last.** Integer division truncates — doing it early loses precision permanently.
- Wrong: `(amount / total_supply) * price`
- Right: `(amount * price) / total_supply`

### 3.3 Price Slippage Checks
- In any function involving pricing, swapping, or purchasing: **require an `expected_price` or `min_amount_out` argument from the user.**
- Without this, MEV bots can manipulate price between submission and execution. The user's transaction lands at a worse price than intended.
- Reject the transaction if the actual price deviates beyond the user-supplied tolerance.

### 3.4 Lamport Balance Invariant
- After every instruction, **the total lamports across all accounts must remain equal.** Never create or destroy lamports — only redistribute.
- When closing an account, the rent-exempt lamports must go to a **trusted destination** (the original initializer or a program-controlled account). Never allow arbitrary destinations — this enables "rent stealing."
- Manually verify lamport math when implementing custom close or de-listing logic.

---

## 4. DUPLICATE MUTABLE ACCOUNT ATTACKS

Passing the same account twice for two different roles is a classic exploit vector.

### 4.1 The Attack
- If your instruction takes `account_a` (source) and `account_b` (destination) and an attacker passes the same account for both, your state writes will conflict. The last write wins (in Anchor, the last serialized field). The net effect is often a free "transfer" to self that bypasses balance checks.

### 4.2 Prevention
- **Always add a constraint ensuring two mutable accounts that must be distinct are actually distinct:**
  ```
  constraint = account_a.key() != account_b.key()
  ```
- If your logic updates different fields of the same account through two references, merge them into a single reference to ensure atomic state updates.
- Ask yourself for every pair of mutable accounts: *"What happens if an attacker passes the same account for both?"*

---

## 5. CROSS-PROGRAM INVOCATIONS (CPI) SAFETY

CPI is the most complex attack surface in Solana. Every CPI is a trust boundary.

### 5.1 Validate Program IDs — No Arbitrary CPI
- **Never invoke a program address provided by the user without verification.** An attacker will pass a malicious program that mimics success responses.
- For well-known programs (System, Token, Token-2022): hardcode their IDs and compare.
- For dynamic programs: check the provided address against a trusted allowlist stored in your program's state account.
- If using `AccountInfo` for the program account: `require_keys_eq!(cpi_program.key(), expected_program::ID)`.

### 5.2 Reload Stale Data After CPI
- **After any CPI that modifies a shared account, reload the account data before using it again.**
- Your in-memory deserialized struct does not update automatically when the on-chain state changes via CPI.
- Missing a reload means you're making decisions on stale balances or state — a classic logic error.

### 5.3 Signer Pass-Through Sanitization
- Any account marked as a signer in your current transaction **remains a signer** in CPIs you make.
- Before passing accounts into an external CPI call, iterate through them and verify `!account.is_signer` unless that privilege is explicitly required.
- Use **account isolation**: derive user-specific PDAs so a compromised CPI signer only has authority over one user's "blast radius," not the entire protocol.

### 5.4 SOL Balance Checks Around CPI (Slippage for SOL)
- Solana has no `msg.value` equivalent — a callee can spend SOL from a signing account.
- Record the signer's balance **before** the CPI: `let balance_before = ctx.accounts.signer.lamports();`
- After the CPI, verify: `require!(balance_before <= balance_after + max_spendable, ErrorCode::ExcessiveSpend);`

### 5.5 Post-CPI Ownership Verification
- An attacker-controlled program can use the `assign` instruction to change an account's owner during a CPI.
- **After any CPI involving an account you care about, verify the owner is still the expected program.**
- `require_keys_eq!(account.owner, &system_program::ID)` (or your program's ID as appropriate).

### 5.6 CPI Return Values — Always Propagate Errors
- **Always wrap CPI calls with the `?` operator** to ensure that if the inner call fails, the entire transaction reverts.
- Never call a CPI and discard its result. Be aware that some programs return "Success" even if their internal conditional logic (like a guarded transfer) did not execute.

### 5.7 invoke vs invoke_signed
- **Prefer `invoke` over `invoke_signed`** wherever possible. Only use `invoke_signed` when a PDA must sign.
- With `invoke_signed`, only extend signer privileges to accounts that are already signers in the current instruction — never elevate non-signers.
- Minimize the accounts passed to any CPI call — pass only what is required, nothing more.

### 5.8 Architecture: Defense-in-Depth
- **Avoid a single "Global Vault" PDA for all users.** If exploited, all user funds are at risk.
- Use **user-specific PDAs for deposits.** A CPI exploit then drains only the affected user's funds — not the entire protocol.

---

## 6. ACCOUNT STORAGE & LIFECYCLE

### 6.1 Storage Rules
- Never store program state in the program account itself. Always use separate data accounts.
- Always set the `owner` field of state accounts to your program's address. This is your primary access control for account data.
- Never allow an account's data to be modified by a program that does not own it.
- Never allow accounts to exceed **10 MiB** of data. Never allow total per-transaction resize to exceed **20 MiB**.

### 6.2 Rent Exemption
- **Always fund new accounts with at least two years' worth of rent** (the rent-exempt threshold).
- Never leave an account in the `0 < balance < minimum_balance` range — it becomes eligible for garbage collection.

### 6.3 Account Closing (Anti-Revival)
- **Never close an account by only draining its lamports.** The account can be "revived" by refunding its rent.
- Proper close sequence:
  1. Set all data bytes to zero (`memset` / `fill(0)`)
  2. Transfer all lamports to the recipient
  3. Transfer ownership back to the System Program
- The destination for rent lamports must be a **trusted address** (original initializer or a controlled account) — never arbitrary.

### 6.4 Sysvar Verification
- When reading from a sysvar (Clock, Rent, SlotHashes, etc.), always verify the account's public key matches the known sysvar address.
- Never trust a sysvar account passed by the user without verification. (The Wormhole hack involved sysvar spoofing.)

---

## 7. TOKEN-2022 COMPATIBILITY

Mixing legacy token functions with Token-2022 mints causes silent DoS.

- **Never use `anchor_spl::token::transfer` (or its native equivalent) for programs that may encounter Token-2022 mints.**
- It hardcodes the legacy Token Program ID and will fail or misbehave with Token-2022 accounts.
- **Always use `transfer_checked`** and the interface-aware versions that dynamically detect the correct program.
- Always provide the `mint` account and `decimals` in transfers — required by `transfer_checked`.
- Token-2022 features (transfer hooks, confidential transfers, interest-bearing tokens) have **expanded attack surface** — flag them in the security checklist for extra manual review.

---

## 8. TRANSACTION MODEL SAFETY

### 8.1 Atomicity
- Compose multiple operations into a single transaction when you need all-or-nothing guarantees.
- Solana's transaction atomicity means either all instructions succeed or all revert — design your program to take advantage of this.

### 8.2 Compute Budget
- Never assume a transaction will succeed past compute budget limits.
- For complex instructions, use `SetComputeUnitLimit` and budget compute units accordingly.
- Unbounded loops over `remaining_accounts` or variable-length collections are a compute DoS vector.

### 8.3 Address Lookup Tables
- Never include signer accounts in an Address Lookup Table. Signer pubkeys must always be inline in the transaction.

### 8.4 Durable Nonces
- Always place `AdvanceNonceAccount` as the **first instruction** in the transaction.
- Never use a nonce account whose blockhash is already recent — this defeats its purpose.

---

## 9. SAFE RUST PATTERNS

### 9.1 Vector Initialization
- To declare a vector of length `N` filled with zeros: use `vec![0; N]` **(semicolon)**.
- **Never use `vec![0, N]` (comma)** — this creates a two-element vector `[0, N]`, not N zeroes. Accessing index 2+ will panic.

### 9.2 Avoid Unsafe Rust
- Unless absolutely necessary for performance, stay within safe Rust.
- The Rust compiler's memory protections are your last line of defense against memory corruption bugs.
- Every `unsafe` block requires an explicit justification comment.

### 9.3 Handle `remaining_accounts` With Full Rigor
- If you iterate over `ctx.remaining_accounts`, apply the **same ownership, signer, and type checks** as you do for named accounts.
- `remaining_accounts` is the easiest place to inject malicious accounts because developers assume they've already been validated.

---

## 10. THE CURIOSITY PRINCIPLE (Mindset)

Security is not a static checklist — it is an adversarial mindset applied at design time.

For every account input in your program, ask:
1. **"What happens if I pass the same account twice?"** → Duplicate mutable account attack.
2. **"What happens if this account is owned by a different program?"** → Type cosplay / ownership bypass.
3. **"What happens if this is a Token-2022 mint instead of a legacy mint?"** → DoS / wrong program invoked.
4. **"What happens if the CPI I'm calling returns success but didn't actually do anything?"** → Silent logic failure.
5. **"What happens if an attacker passes a valid-looking but malicious program ID?"** → Arbitrary CPI.
6. **"What's the worst-case scenario if this account's bump is not canonical?"** → PDA collision.

Apply this curiosity to every design decision, not just during code review.
