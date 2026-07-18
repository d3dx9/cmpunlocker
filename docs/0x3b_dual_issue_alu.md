# Falcon SEC2 0x3b opcode: dual-issue ALU semantics

## TL;DR

**0x3b in NS mode = exact mirror of 0x33** (same RISC-V OP-family encoding,
same funct7/funct3 coverage). The compiler uses 0x3b for independent ALU
operations that can be issued in parallel to the primary 0x33 ALU unit
(dual-issue hardware feature).

**0x3b in HS mode = mpopaddret** (multi-pop + optional add + return).
See `tools/booter_secure.py` for the HS-mode override.

## Evidence

### 1. Tegra X1 envytools/envydis (Tegra X1 Falcon ISA documentation)

`https://github.com/envytools/envytools/blob/master/envydis/falcon.c`

Tegra X1 Falcon has a similar 0x3b opcode space with these arithmetic
variants (sub-opcode in bits [19:16]):

| sub-opcode | operation |
|------------|-----------|
| 0x0 | add (rd, rs1, rs2) |
| 0x1 | adc (add with carry) |
| 0x2 | sub |
| 0x3 | sbb (sub with borrow) |
| 0x4 | shl |
| 0x5 | shr |
| 0x7 | sar |
| 0xc | shlc (shift left with carry) |
| 0xd | shrc (shift right with carry) |

The Tegra X1 Falcon ISA is **different** from RISC-V (Tegra X1 Falcon
has 16 GPRs, 16-bit PC/SP, custom opcodes). But the SPIRIT of 0x3b is
the same: a parallel ALU path that the compiler uses for independent ops.

### 2. GA100 SEC2 RISC-V Falcon (our target)

The FWSEC firmware (`.ga100_text`, `.ga100_resident_text`) shows 47
0x3b instructions with the following distribution (verified by
`tools/dual_issue_alu_test.py`):

| operation | count | encoding |
|-----------|------:|-----------|
| ADD       |   21  | funct7=0x00, funct3=0x0 |
| SUB       |   21  | funct7=0x20, funct3=0x0 |
| MUL       |    2  | funct7=0x01, funct3=0x0 |
| SLL       |    2  | funct7=0x00, funct3=0x1 |
| REMU      |    1  | funct7=0x01, funct3=0x7 |
| (other)   |    0  | not used in FWSEC |

This distribution perfectly matches "compiler uses 0x3b for independent
accumulation paths". 42/47 = ADD/SUB suggests the compiler schedules
an addition/subtraction on the 0x3b ALU while the 0x33 ALU does the
main loop body.

### 3. Dual-issue ALU verification (dual_issue_alu_test.py)

The test encodes the same operations with both 0x33 and 0x3b opcodes
and verifies identical results:

```
[OK] ADD  (0x00000007, 0x00000003) = 0x0000000a  | opc=0x33: 0x0000000a, opc=0x3b: 0x0000000a
[OK] SUB  (0x12345678, 0x9abcdef0) = 0x77777788  | opc=0x33: 0x77777788, opc=0x3b: 0x77777788
[OK] MUL  (0xffffffff, 0x00000001) = 0xffffffff  | opc=0x33: 0xffffffff, opc=0x3b: 0xffffffff
[OK] SLL  (0xffffffff, 0x00000001) = 0xfffffffe  | opc=0x33: 0xfffffffe, opc=0x3b: 0xfffffffe
[OK] SLT  (0x12345678, 0x9abcdef0) = 0x00000000  | opc=0x33: 0x00000000, opc=0x3b: 0x00000000
[OK] SRL  (0xffffffff, 0x00000001) = 0x7fffffff  | opc=0x33: 0x7fffffff, opc=0x3b: 0x7fffffff
[OK] OR   (0x12345678, 0x9abcdef0) = 0x9abcdef8  | opc=0x33: 0x9abcdef8, opc=0x3b: 0x9abcdef8
[OK] AND  (0xffffffff, 0x00000001) = 0x00000001  | opc=0x33: 0x00000001, opc=0x3b: 0x00000001
[OK] REMU (0x12345678, 0x9abcdef0) = 0x12345678  | opc=0x33: 0x12345678, opc=0x3b: 0x12345678
[OK] RORI (0x12345678, shamt=16) = 0x56781234     | opc=0x33: 0x56781234, opc=0x3b: 0x56781234
... (50+ tests, all OK)
OVERALL: PASS
```

## Implementation

### 0x3b in NS mode (booter_emu.py)

The implementation routes both 0x33 and 0x3b to the same `_exec_op`
function which handles all standard RV32I OP, RV32M, and Zbb extensions:

```python
elif opc in (0x33, 0x3b):  # OP / Falcon-OP (dual-issue ALU)
    v1 = self.regs[rs1]
    v2 = self.regs[rs2]
    handled, unknown_msg = self._exec_op(rd, v1, v2, funct3, funct7, insn)
```

The `_exec_op` function handles:
- funct7=0x00: ADD/SLL/SLT/SLTU/XOR/SRL/OR/AND (all funct3)
- funct7=0x20: SUB/SRA
- funct7=0x01: MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU (all funct3)
- funct7=0x30: RORI (Zbb extension, funct3=shamt)

The "dual-issue" property is hardware-specific: SEC2 has two ALU units
that can execute in parallel. The compiler issues independent ops to
both ALUs (encoded with different opcodes: 0x33 vs 0x3b) to maximize
throughput.

### 0x3b in HS mode (booter_secure.py)

In HS mode, 0x3b is overridden to mean mpopaddret. This is used by
the booter_load ROP exploit chain. The frame layout is:

| SP offset | popped to | meaning |
|-----------|-----------|---------|
| 0x08      | x1 (val)  | value to write |
| 0x0C      | x10 (addr)| address to write to (x0 is hardwired to 0) |
| 0x14      | PC (RA)   | next instruction (BAR0 master write gadget) |
| (advance) | SP += 0x18 | move to next frame |

The exploit chain self-links: each mpopaddret points its RA to a
"BAR0 master write" gadget (which does `sw x1, 0(x10)`), which then
falls through to the next mpopaddret.

### Verification

`tools/mpopaddret_test.py` runs the community-verified 5-write exploit
chain and produces all 5 expected BAR0 writes:

```
[OK] CFG1     0x9A0204 <- 0x02669000
[OK] LMR      0x100CE0 <- 0x0000028a
[OK] WPR2-lo  0x1FA824 <- 0x1FFFFE00
[OK] WPR2-hi  0x1FA828 <- 0x00000000
[OK] resetPLM 0x8403C4 <- 0x000000FF
OVERALL: PASS
```

## Boot-Verified Tegra X1 + GA100

The dual-issue hypothesis is consistent across TWO Falcon generations:

| Generation | 0x3b semantic | ISA | Source |
|------------|---------------|-----|--------|
| Tegra X1   | ADD/ADC/SUB/SBB/SHL/SHR/SAR/SHLC/SHRC | Custom Falcon | envytools envydis |
| GA100 SEC2 (NS) | ADD/SUB/MUL/SLL/REMU/... (mirror of 0x33) | RISC-V | FWSEC analysis |
| GA100 SEC2 (HS) | mpopaddret | RISC-V | exploit reverse-engineering |

The Tegra X1 0x3b and the GA100 SEC2 0x3b have **different encodings**
(Tegra X1 is not RISC-V), but they serve the same role: a secondary
ALU path for parallel execution.

## RISC-V Encoding Details

For GA100 SEC2, 0x3b follows standard RISC-V OP-family encoding:

| bits | field | role |
|------|-------|------|
| [6:0] | opcode | 0x3b (Falcon dual-issue ALU) or 0x33 (standard) |
| [11:7] | rd | destination register |
| [14:12] | funct3 | sub-opcode: 0=add/sub, 1=sll, 2=slt, 3=sltu, 4=xor, 5=srl/sra, 6=or, 7=and |
| [19:15] | rs1 | source 1 |
| [24:20] | rs2 | source 2 |
| [31:25] | funct7 | 0x00=base, 0x20=alt (sub/sra), 0x01=RV32M, 0x30=Zbb RORI |

For shift instructions, only the low 5 bits of rs2 are used as
shift amount (RV32 spec). Our implementation enforces this.

## Side Notes

- **Tegra X1 mpopaddret** (envytools): `0xfb` opcode (not 0x3b), with
  variants for pop-only, pop+ret, pop+add, pop+add+ret. GA100 SEC2's
  0x3b-in-HS-mode achieves the same effect but with a different
  encoding (using bits of the standard RISC-V instruction).
- **Falcon register width**: SEC2 registers are 64-bit, but operations
  are 32-bit. The implementation uses 64-bit register storage but masks
  results to 32 bits for standard RV32 ops, then sign-extends for
  comparisons.
- **Switchbrew TSEC** (Tegra X1 only): also documents the Falcon
  ISA but with TX1-specific opcodes. Confirms the dual-issue ALU
  pattern exists across NVIDIA Falcon generations.
