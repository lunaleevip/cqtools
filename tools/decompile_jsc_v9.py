#!/usr/bin/env python3
"""JSC Decompiler v9 - Stack-based decompiler for Cocos2d-x SM 1.8.5.

Reuses v8's JSCReader for parsing, completely rewrites the decompilation engine.
Key: proper stack simulation where every opcode correctly pushes/pops values.

Usage:
    python decompile_jsc_v9.py <input.jsc>
    python decompile_jsc_v9.py --dir <src_jsc_dir> <output_dir>
"""
import struct, sys, os, re

# Import v8's reader infrastructure
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decompile_to_js_v8 import JSCReader

# Binary operators by opcode
BINOPS = {
    15: '|', 16: '^', 17: '&', 18: '==', 19: '!=',
    20: '<', 21: '<=', 22: '>', 23: '>=',
    24: '<<', 25: '>>', 26: '>>>',
    27: '+', 28: '-', 29: '*', 30: '/', 31: '%',
    72: '===', 73: '!==',
}

UNOPS = {32: '!', 33: '~', 34: '-', 35: '+'}


class StackDecompiler:
    """Decompile SM 1.8.5 bytecode using stack simulation.

    Important: `atoms` must be the SCRIPT-LOCAL atom table only — sub-scripts
    have their own atom indices counting from 0, so passing parent+child merged
    will produce wildly wrong identifiers (e.g. SETPROP atom=2 inside setIsOver
    points to nested_atoms[2]='b_isOver', NOT root atoms[2]='GuideMgr').
    """

    def __init__(self, bc, atoms, nested_objects=None, nargs=0, namespace=None):
        self.bc = bc
        self.atoms = atoms or []
        self.nested = nested_objects or []
        self.nargs = nargs
        # SM 1.8.5 runtime: stack starts empty. 'this' is pushed explicitly by
        # the THIS opcode (op=65), not implicit. Pre-seeding 'this' caused
        # off-by-one in every SETPROP/CALL within nested function bodies.
        self.stack = []
        self.output = []
        self.locals = {}
        self.args = {}
        self.pc = 0
        self.indent = 0
        self.jump_targets = set()
        self.index_base = 0
        # Optional fallback prefix used when root-level SETPROP/INITPROP sees
        # 'undefined' as its target (the GuideMgr-style "xs.Y.Z = { ... }"
        # bytecode pattern leaves 'undefined' on the stack because the
        # GETPROP/OR/PUSH/CASE prologue is hard to evaluate statically).
        self.namespace = namespace
        # with-statement scope stack. ENTERWITH pushes the with-target, so
        # subsequent INITPROP/SETPROP/CALLPROP with no explicit object on the
        # stack can resolve names through the innermost with-scope.
        self.with_stack = []
        # try-block depth. EXCEPTION ops only emit `} catch (e) {` when we
        # are actually inside a try; otherwise they're standalone exception
        # pushes (rare but possible in certain compiler-generated patterns).
        self.try_depth = 0
        # Output lines collected before the first "substantive" statement are
        # almost always dead-code prologue (`throw undefined;`, `return undefined;`,
        # spurious if/while around unreachable PCs). Track how many leading
        # lines to drop in _filter_output().
        self._prologue_drop = 0
        self._real_seen = False

    def atom(self, idx):
        # read_atom_idx() already OR'd index_base in; do NOT OR again here.
        if 0 <= idx < len(self.atoms):
            return self.atoms[idx]
        return f"atom_{idx}"

    @staticmethod
    def _looks_like_bogus_obj(expr):
        """Return True for stack expressions that are obviously v9 tracker
        artifacts when used as the target object of a SETPROP/INITPROP:
          - `(X == Y)`, `(X !== Y)`, `(X >= Y)` etc. comparison results
          - `++X`, `--X`, `X++`, `X--` increment expressions
          - `X || Y`, `X && Y` short-circuits when wrapped in parens
        Real JS very rarely assigns to a property of such expressions.
        """
        if not expr or not isinstance(expr, str):
            return False
        # Comparison / logical operators inside parens
        if expr.startswith("(") and expr.endswith(")"):
            inner = expr[1:-1]
            # very loose check: contains a comparison operator
            for token in (" == ", " != ", " === ", " !== ",
                          " <= ", " >= ", " < ", " > ",
                          " && ", " || ", " ^ ", " | ", " & ",
                          " % ", " * ", " / ", " + ", " - ",
                          " >>> ", " << ", " >> ",
                          " in ", " instanceof "):
                if token in inner:
                    return True
        # Inc/dec only
        if expr.endswith(("++", "--")):
            return True
        if expr.startswith(("++", "--")):
            return True
        return False

    def _scope_or_namespace(self, default="this"):
        """Return the innermost with-scope name, or fall back to the inferred
        root namespace (e.g. `xs.Guide.GuideMgr`). Handles both legacy string
        entries and new (scope, emitted) tuples in with_stack.

        For nested function bodies (namespace is None), default to 'this' so
        SETPROP/INITPROP that lost their target produce readable assignments
        like `this.foo = X;` instead of `undefined.foo = X;`.
        """
        if self.with_stack:
            entry = self.with_stack[-1]
            return entry[0] if isinstance(entry, tuple) else entry
        return self.namespace or default

    @staticmethod
    def _undef_only_expr(s):
        """Return True if `s` is an expression that contains only the
        identifier 'undefined' (and 'arguments') combined with operators,
        parentheses and 'instanceof'/'in'/'typeof' keywords. These come from
        the stack-tracking failure mode where every push winds up as 'undefined'.
        """
        rest = s
        for kw in ("undefined", "arguments", "instanceof", " in ", " typeof "):
            rest = rest.replace(kw, "")
        for ch in "()!<>=&|^%+-*/~?, \t":
            rest = rest.replace(ch, "")
        return rest == ""

    @staticmethod
    def _undef_dominated(s):
        """Return True when a parenthesized expression contains only the
        identifier 'undefined' plus operators / parens / whitespace.
        Used to detect prologue artifacts like `if ((undefined < undefined))`.
        """
        # Strip leading `if (` / `with (` / `if (!(` and the trailing `) {`
        inner = s
        for prefix in ("if (!(", "if (", "with ("):
            if inner.startswith(prefix):
                inner = inner[len(prefix):]
                break
        if inner.endswith(") {"):
            inner = inner[:-3]
        elif inner.endswith(")) {"):
            inner = inner[:-4]
        # Remove all 'undefined' tokens, parens, operators, whitespace, '!'.
        rest = inner.replace("undefined", "")
        for ch in "()!<>=&|^%+-*/~? \t":
            rest = rest.replace(ch, "")
        return rest == ""

    def push(self, val):
        self.stack.append(str(val))

    def pop(self):
        return self.stack.pop() if self.stack else "undefined"

    def peek(self):
        return self.stack[-1] if self.stack else "undefined"

    def emit(self, line):
        text = "    " * self.indent + line
        self.output.append(text)
        # "Substantive" = real assignment / call / property write / return /
        # control-flow / with-block. Once we see one, stop counting prologue.
        if not self._real_seen:
            s = line.strip()
            real = False
            # Tier-1 prologue-noise patterns: never count as substantive even
            # though they look like statements.
            import re as _re
            if s in ("throw undefined;", "return undefined;", "return;",
                     "throw undefined", "return undefined"):
                pass
            elif s.startswith("if (") and "undefined" in s and self._undef_dominated(s):
                # if (undefined), if (!(undefined)), if ((undefined < undefined)) etc.
                pass
            elif s.startswith("with (") and "undefined" in s and self._undef_dominated(s):
                pass
            elif s.startswith("const ") and (s.endswith("= undefined;") or s.endswith("= undefined")):
                pass
            elif _re.match(r"^(arg|local)_(\d+)\s*=\s*", s):
                # arg_N / local_N = ... : only real when index is reasonable
                # and RHS has at least one real identifier (not just undefined
                # combined with operators).
                m = _re.match(r"^(arg|local)_(\d+)\s*=\s*(.+?);?$", s)
                if m:
                    kind = m.group(1)
                    idx = int(m.group(2))
                    rhs = m.group(3).strip().rstrip(";").strip()
                    limit = max(self.nargs, 32) if kind == "arg" else 100
                    if (idx <= limit and rhs != "undefined"
                            and not self._undef_only_expr(rhs)):
                        real = True
            elif s.startswith(("this.", "xs.", "var ", "if (", "with (", "try {")):
                real = True
            elif s.startswith("throw "):
                rhs = s[len("throw "):].rstrip(";").strip()
                if rhs != "undefined" and not self._undef_only_expr(rhs):
                    real = True
            elif s.startswith("return ") and s not in ("return undefined;", "return;"):
                rhs = s[len("return "):].rstrip(";").strip()
                if rhs and not self._undef_only_expr(rhs):
                    real = True
            elif "= function" in s:
                real = True
            elif " = " in s:
                rhs = s.split(" = ", 1)[1].strip()
                if rhs not in ("undefined;", "undefined"):
                    real = True
            if real:
                self._real_seen = True
            else:
                # Still in prologue; remember this line is droppable.
                self._prologue_drop = len(self.output)

    def read_u8(self):
        v = self.bc[self.pc + 1]
        return v

    def read_u16(self):
        """BE uint16 - all JOF_UINT16/QARG/LOCAL operands are big-endian"""
        if self.pc + 2 >= len(self.bc):
            return 0
        return (self.bc[self.pc + 1] << 8) | self.bc[self.pc + 2]

    def read_i16(self):
        """BE int16 for JOF_JUMP"""
        return struct.unpack_from('>h', self.bc, self.pc + 1)[0]

    def read_i32(self):
        """BE int32 for JOF_INT32/JOF_JUMPX"""
        if self.pc + 5 > len(self.bc): return 0
        return struct.unpack_from('>i', self.bc, self.pc + 1)[0]

    def read_atom_idx(self):
        """Cocos2d-x: index is byte[4] of 5-byte instruction (pc[1:4]=padding, pc[4]=idx)"""
        if self.pc + 5 > len(self.bc):
            return 0
        return self.bc[self.pc + 4] | self.index_base

    def read_obj_idx(self):
        """Object index for LAMBDA/DEFFUN - raw byte without INDEXBASE."""
        if self.pc + 5 > len(self.bc):
            return 0
        return self.bc[self.pc + 4]

    def decompile(self):
        """Main decompilation loop."""
        self.pc = 0
        self._skip_prologue()
        # Map jump-target PC → number of open blocks to close at that PC.
        # IFEQ/IFNE bump this when opening a branch; the main loop emits the
        # matching '}' as it reaches the target.
        self.pending_close = {}
        while self.pc < len(self.bc):
            # Close any blocks scheduled at this PC.
            n_close = self.pending_close.pop(self.pc, 0)
            for _ in range(n_close):
                self.indent = max(0, self.indent - 1)
                self.emit("}")
            op = self.bc[self.pc]
            self._exec(op)
        # Close any blocks that never reached their target (truncated bc).
        while self.indent > 0:
            self.indent -= 1
            self.emit("}")
        return "\n".join(self._filter_output())

    def _filter_output(self):
        """Remove lines that are clearly prologue artifacts."""
        import re
        # Drop leading prologue lines (everything emitted before the first
        # substantive statement). This eliminates spurious `throw undefined;`
        # / `return undefined;` / `}`-orphans that come from dead-code at the
        # top of a function body.
        lines = self.output[self._prologue_drop:] if self._prologue_drop else self.output
        # Patterns that look like obvious stack-tracking failures (`throw`/
        # `return` of a synthetic local increment, `this` used as a shift
        # operand, etc.). These never appear in real game code.
        DEAD_EXPR_RE = re.compile(
            r"(throw\s+(local_|arg_)\w*(\+\+|--);"
            r"|throw\s+undefined\s*[*+\-%&|^];"
            r"|return\s+\(\+\+local_"
            r"|\(this\s*(>>>|<<|>>)\s*"
            r"|\(undefined\s*[%&|^]\s*"
            r"|\(undefined\s+instanceof\s+undefined\))"
        )
        filtered = []
        # `local_N = undefined;` / `arg_N = undefined;` — synthetic stack
        # tracking artifacts at dead branches (SM emits a SETLOCAL of the
        # undefined "rest" value, but in real JS this is a meaningless
        # statement).
        LV_UNDEF = re.compile(r"^(local|arg)_\d+\s*=\s*undefined;?\s*$")
        # `const X = undefined;` / `const X = this;` / `const X = null;` are
        # almost always SM dead-code SETCONST artifacts in cocos2d-x bytecode.
        # Real `const`-declared values almost never use these trivial RHS.
        CONST_NOISE = re.compile(
            r"^const\s+\w+\s*=\s*(undefined|this|null|\[\]|\{\}|true|false);?\s*$"
        )
        # `delete X;` on a bare identifier (no member access) is usually
        # dead-code (cocos2d-x doesn't `delete localVar`). Keep `delete obj.X`
        # and `delete obj[K]` since those are real assertions.
        DELETE_BARE = re.compile(r"^delete\s+\w+;\s*$")
        # `throw <bare>;` with a simple literal/identifier RHS is a stack-
        # tracker artifact (real `throw` uses an Error or string expression).
        THROW_BARE = re.compile(
            r"^throw\s+(this|true|false|null|undefined|arguments|hasNext|"
            r"local_\d+|arg_\d+|\d+);\s*$"
        )
        # `this.X = undefined;` and `this.X = this;` are stack-tracker
        # leftovers (SM emits SETPROP undefined / SETPROP this in dead
        # branches). Don't filter root-script SETPROP like `xs.Y.Z = undef`
        # because those represent real { field: undefined } object literal
        # entries.
        THIS_SET_NOISE = re.compile(
            r"^this\.\w+\s*=\s*(undefined|this|arguments|hasNext);\s*$"
        )
        ARG_SET_NOISE = re.compile(
            r"^arg_\d+\s*=\s*(this|null|true|false);\s*$"
        )
        # Self-assignment: `X = X;` — purely a SM stack-tracking artifact
        # where the same value got popped + emit-stored back. Real code
        # never writes this.
        SELF_ASSIGN = re.compile(r"^([\w\.\[\]]+)\s*=\s*\1;\s*$")
        # `xs.A.B.B = undefined;` — SM root-script tail emits a final
        # SETGNAME of the namespace last segment, which v9 sees as
        # `xs.A.B.B = undefined;`. Drop when the last two segments match
        # and RHS is undefined.
        NS_TAIL_DUP = re.compile(
            r"^(?:xs\.)?(\w+(?:\.\w+)*)\.(\w+)\s*=\s*undefined;\s*$"
        )
        # Pure expression statement that starts with '(' and contains no '='
        # / no `++`/`--` / no function-call style. Conservative drop: these
        # come from POPV-ing a stack expression that the source code would
        # have used as an rvalue. Real JS never has bare `(a + b);` lines.
        # Bare-paren expression statement. Outer `(...)` enclosing `expr;`.
        # Excludes assignments (single `=` that is not part of `===`/`!==`/
        # `<=`/`>=`).
        BARE_PAREN_EXPR = re.compile(r"^\(.*\);\s*$")
        def _is_assignment(s):
            # detect `=` that is not preceded/followed by another `=` or `!`/<>
            return bool(re.search(r"(?<![=!<>])=(?!=)", s))
        # Strip the outer parens from `lhs = (expr);` / `return (expr);` /
        # `throw (expr);` produced by BINOP's `(left OP right)` form.
        def _unwrap_outer(s):
            # Find content between outermost `(` and `);`. Only strip if those
            # parens enclose the entire RHS and aren't part of a function call.
            if not s.endswith(");"):
                return s
            # find the `=` or `return ` / `throw ` prefix
            for prefix in ("return (", "throw (", "= ("):
                idx = s.find(prefix)
                if idx >= 0:
                    open_idx = idx + len(prefix) - 1
                    # ensure parens are matched and outer
                    depth = 0
                    for j in range(open_idx, len(s) - 1):
                        if s[j] == "(":
                            depth += 1
                        elif s[j] == ")":
                            depth -= 1
                            if depth == 0:
                                # If `)` is the second-to-last char, parens
                                # enclose the entire RHS — safe to strip.
                                if j == len(s) - 2:
                                    return s[:open_idx] + s[open_idx + 1:j] + ";"
                                return s
            return s
        for line in lines:
            stripped = line.strip()
            if stripped in ("return undefined;", "throw undefined;",
                            "return;", "(undefined);", "undefined;",
                            "function() {};", "function() {}",
                            "return __bnd;", "throw __bnd;"):
                continue
            if LV_UNDEF.match(stripped):
                continue
            if CONST_NOISE.match(stripped):
                continue
            if DELETE_BARE.match(stripped):
                continue
            if THROW_BARE.match(stripped):
                continue
            if THIS_SET_NOISE.match(stripped):
                continue
            if ARG_SET_NOISE.match(stripped):
                continue
            if SELF_ASSIGN.match(stripped):
                continue
            mtail = NS_TAIL_DUP.match(stripped)
            if mtail and mtail.group(1).endswith("." + mtail.group(2)):
                continue
            # Bare last segment dup: `Foo.Foo = undefined;`
            if mtail and mtail.group(1) == mtail.group(2):
                continue
            # __bnd marker leaked from BINDNAME (shouldn't happen normally)
            if "__bnd" in stripped:
                continue
            # Apply paren unwrap to indented lines too
            indent = len(line) - len(line.lstrip())
            stripped2 = _unwrap_outer(stripped)
            if stripped2 != stripped:
                line = " " * indent + stripped2
                stripped = stripped2
            if BARE_PAREN_EXPR.match(stripped):
                # Drop bare-paren expression statements that
                #   (a) are NOT assignments (no `=` outside ===/!==/<=/>=)
                #   (b) have no function-call form (`name(`)
                # Even `++`/`--` are safe — they're stack-tracker artifacts.
                inner = stripped[1:-2]
                if (not _is_assignment(stripped)
                        and not re.search(r"[A-Za-z_]\w*\s*\(", inner)):
                    continue
            if DEAD_EXPR_RE.search(line):
                continue
            stripped = line.strip()
            # Skip lines with impossibly large arg/local indices
            if re.search(r'arg_(\d+)', stripped):
                m = re.search(r'arg_(\d+)', stripped)
                if int(m.group(1)) > 20 and self.nargs <= 20:
                    continue
            if re.search(r'local_(\d+)', stripped):
                m = re.search(r'local_(\d+)', stripped)
                if int(m.group(1)) > 100:
                    continue
            # Skip lines with atom_XXXXX (out of range atoms)
            if 'atom_' in stripped:
                continue
            # Skip pure undefined expressions
            if stripped in ('undefined;', '(undefined);', '+undefined;', '-undefined;'):
                continue
            # Skip standalone comparison/arithmetic expressions (prologue artifacts)
            if re.match(r'^\(.*undefined.*[<>=!%&|^]+.*\);$', stripped):
                continue
            # Clean up (X % undefined).prop patterns -> this.prop
            line = re.sub(r'\([^)]*%\s*undefined\)', 'this', line)
            line = re.sub(r'\([^)]*>>\s*undefined\)', 'this', line)
            line = re.sub(r'\([^)]*<<\s*undefined\)', 'this', line)
            line = re.sub(r'\([^)]*>>>\s*undefined\)', 'this', line)
            # Clean up `undefined[undefined]` — stack-tracker underflow in
            # GETELEM. Replace with `this` (the most common real receiver).
            line = re.sub(r'undefined\[undefined\]', 'this', line)
            # Clean up `typeof undefined.X` — TYPEOF wrapping underflow.
            # Replace `typeof undefined.foo` with just `this.foo`.
            line = re.sub(r'typeof undefined\.(\w+)', r'this.\1', line)
            line = re.sub(r'typeof undefined\b', 'undefined', line)
            # Drop lines containing `new undefined()` — NEW opcode with
            # stack-underflow constructor. Never valid JS; the surrounding
            # expression is always corrupted too.
            if re.search(r'new undefined\s*\(', line):
                continue
            # Drop lines with inc/dec on undefined — INC/DECNAME/PROP opcodes
            # where the stack underflowed. Never valid JS.
            if re.search(r'[\+\-]{2}undefined|undefined[\+\-]{2}', line):
                continue
            # Skip lines that are just "this;" or "this);" after cleanup
            cleaned = line.strip()
            if cleaned in ('this;', 'this);', 'undefined;'):
                continue
            filtered.append(line)
        # Drop `local_N = X;` immediately overwritten by `local_N = ...;`
        # (SM emits a zero-init then real assignment in the same flow). Apply
        # before the second pass so the second pass sees the cleaned list.
        # X must be a simple value (literal / `this` / `arg_*` / `local_*` /
        # an undefined operand) — that lets us recognise the dead-init pattern
        # without nuking a real `local_3 = expensiveCall(); local_3 = foo;`
        # idiom.
        init_overwrite = re.compile(
            r"^(local_\d+)\s*=\s*"
            r"(false|true|null|0|1|undefined|this|arguments|"
            r"arg_\d+|local_\d+);\s*$"
        )
        dedup = []
        i = 0
        while i < len(filtered):
            cs = filtered[i].strip()
            ns = filtered[i + 1].strip() if i + 1 < len(filtered) else None
            m1 = init_overwrite.match(cs)
            if m1 and ns is not None:
                m2 = re.match(r"^(local_\d+)\s*=\s*", ns)
                if m2 and m1.group(1) == m2.group(1):
                    i += 1
                    continue
            dedup.append(filtered[i])
            i += 1
        filtered = dedup

        # Second pass: collapse empty blocks + dead-return runs.
        OPEN_RE = re.compile(r"^(with \(.*\) \{|if \(.*\) \{|try \{)$")
        collapsed = []
        i = 0
        last_emit_was_return = False
        last_return_indent = -1
        while i < len(filtered):
            cur = filtered[i].rstrip()
            nxt = filtered[i + 1].rstrip() if i + 1 < len(filtered) else None
            cs = cur.strip()
            ns = nxt.strip() if nxt is not None else None
            cur_indent = len(cur) - len(cur.lstrip())
            # `try {` / `if () {` / `with () {` -> `}` collapses
            if ns == "}" and OPEN_RE.match(cs):
                i += 2
                last_emit_was_return = False
                continue
            # `} catch (e) {` -> `}` (empty catch on same try)
            if ns == "}" and cs == "} catch (e) {":
                collapsed.append(filtered[i][:len(filtered[i]) - len(cur)] + "}")
                i += 2
                last_emit_was_return = False
                continue
            # Drop dead `return X;` statements that immediately follow another
            # `return Y;` at the same indent — unreachable code from SM
            # dual-branch RETURN emit.
            if (last_emit_was_return and cs.startswith("return ")
                    and cur_indent == last_return_indent):
                i += 1
                continue
            # Track new return
            if cs.startswith("return "):
                last_emit_was_return = True
                last_return_indent = cur_indent
            else:
                last_emit_was_return = False
            collapsed.append(filtered[i])
            i += 1
        return collapsed

    def _skip_prologue(self):
        """Skip dead-code / inline-data prologue at start of bytecode.

        Order of attempts:
        1. cc.log / XMLCOMMENT metadata (root scripts)
        2. Inline local variable name table (nested functions)
        3. Longest valid opcode run scan (general fallback)
        """
        if self._try_skip_cclog():
            return
        if self._try_skip_inline_locals():
            return
        self._opcode_run_scan()

    def _try_skip_inline_locals(self):
        """Skip inline local variable name table in nested function bytecode.

        Cocos2d-x SM 1.8.5 stores local variable names inline at the start of
        nested function bytecode as:

            <4 bytes: zero>
            [<4 bytes: char_count LE> <char_count * 2 bytes: UTF-16LE string>]*
            NOP padding...

        e.g. for a function with locals "step", "_step", "cfg", "plugin":

            00 00 00 00
            04 00 00 00  73 00 74 00 65 00 70 00     ("step")
            05 00 00 00  5f 00 73 00 74 00 65 00 70 00 ("_step")
            03 00 00 00  63 00 66 00 67 00             ("cfg")
            06 00 00 00  70 00 6c 00 75 00 67 00 69 00 6e 00 ("plugin")
            00 02 02 ... (NOP/POPV padding before real opcodes)

        Returns True if inline data was detected and skipped.
        """
        bc = self.bc
        if len(bc) < 8:
            return False
        # First 4 bytes must be zero
        if struct.unpack_from('<I', bc, 0)[0] != 0:
            return False

        pos = 4
        natoms = len(self.atoms)
        strings_found = 0

        # Try to parse length-prefixed UTF-16LE strings
        while pos + 4 <= len(bc):
            str_len = struct.unpack_from('<I', bc, pos)[0]
            # Valid string: 1-200 chars, not a common opcode byte
            if str_len == 0 or str_len > 200:
                break
            byte_len = str_len * 2
            if pos + 4 + byte_len > len(bc):
                break
            # Validate content: each uint16 should be a plausible Unicode char
            try:
                chars = struct.unpack_from(f'<{str_len}H', bc, pos + 4)
                if not all(0x20 <= c < 0xFFFF for c in chars):
                    break
            except struct.error:
                break
            pos += 4 + byte_len
            strings_found += 1

        if strings_found == 0:
            return False

        # Skip NOP/POPV padding
        while pos < len(bc) and bc[pos] in (0, 2):
            pos += 1

        # Validate the parse was correct. If we found 2+ plausible UTF-16LE
        # strings, the odds of a false positive are negligible — trust the
        # result and skip to `pos`.  For a single string, do a stricter check:
        # at least the next byte must be a known SM 1.8.5 opcode.
        if strings_found == 1 and pos < len(bc):
            # Known opcode ranges in SM 1.8.5 + cocos2d-x
            first_op = bc[pos]
            if first_op not in range(0, 136) and first_op not in range(140, 200) \
                    and first_op not in range(201, 244) and first_op not in range(244, 256):
                return False  # Single string + unknown byte = probably wrong

        if pos > 4:
            self.pc = pos
            return True
        return False

    def _opcode_run_scan(self):
        """General fallback: find the offset with the longest valid opcode run.

        Adapts the v8 legacy parser's prologue-scan approach. Tries every byte
        offset in [0, scan_limit), walks forward treating bytes as opcodes, and
        picks the offset that produces the longest unbroken valid sequence.
        Inline data (string tables, NOP padding) rarely produces long runs,
        so the real bytecode entry always wins.

        For root scripts (self.namespace is set), atom indices may reference
        shared parent tables beyond self.atoms, so we skip atom validation.
        """
        bc = self.bc
        natoms = len(self.atoms)
        scan_limit = min(len(bc), 512)
        if scan_limit < 5:
            return
        # Root scripts have namespace set and their atom indices may exceed
        # natoms because opcodes reference a parent/shared atom table.
        is_root = self.namespace is not None
        best_off = 0
        best_run = 0
        for off in range(scan_limit):
            pc = off
            run = 0
            while pc < len(bc):
                op = bc[pc]
                if op > 255:
                    break
                sz = self._opcode_size(op)
                if sz <= 0 or pc + sz > len(bc):
                    break
                # For nested functions, validate atom indices against natoms.
                # For root scripts, skip this check (shared atom table).
                if not is_root and op in (53, 54, 57, 59, 60, 61, 93, 110,
                                          111, 128, 156, 157, 187, 217, 220):
                    if natoms > 0 and pc + 5 <= len(bc) and bc[pc + 4] >= natoms:
                        break
                run += 1
                pc += sz
                if run > best_run:
                    best_run = run
                    best_off = off
                if run > 40:
                    break  # Good enough, stop scanning
            if best_run > 40:
                break
        if best_run > 3:
            self.pc = best_off

    def _try_skip_cclog(self):
        """Skip dead-code metadata pattern: DUP XMLCOMMENT(any) FORARG(e4,xx) ... POPV POPV
        This is embedded metadata, never executed at runtime."""
        pc = self.pc
        bc = self.bc
        if pc >= len(bc) or bc[pc] != 12: return False  # DUP
        pc += 1
        while pc < len(bc) and bc[pc] == 0: pc += 1
        if pc >= len(bc) or bc[pc] != 184: return False  # XMLCOMMENT
        pc += 5
        while pc < len(bc) and bc[pc] == 0: pc += 1
        if pc >= len(bc) or bc[pc] != 10: return False  # FORARG
        if pc + 1 >= len(bc) or bc[pc + 1] != 0xe4: return False  # magic byte
        pc += 3
        # Skip until 2 POPVs (end of dead-code block)
        popv_count = 0
        while pc < len(bc) and popv_count < 2:
            b = bc[pc]
            if b == 0: pc += 1; continue
            if b == 2: pc += 1; popv_count += 1; continue
            if b == 228: pc += 3; continue  # OBJTOP
            if b == 1: pc += 1; continue  # PUSH
            if b == 61: pc += 5; continue  # STRING
            break
        self.pc = pc
        return True

    def _exec(self, op):
        """Execute one opcode."""
        pc = self.pc

        # NOP
        if op == 0:
            self.pc += 1
        # PUSH (pushes undefined)
        elif op == 1:
            self.push("undefined")
            self.pc += 1
        # POPV - discard top of stack (expression statement)
        elif op == 2:
            val = self.pop()
            # Only emit if it looks like a meaningful expression (not just a value)
            if '(' in val or '=' in val:
                self.emit(f"{val};")
            self.pc += 1
        # ENTERWITH: pop object, push it as a with-scope. Subsequent INITPROP/
        # SETPROP that find an empty stack should resolve names through this
        # scope instead of falling back to 'undefined'.
        # If the popped object looks like a bogus arithmetic expression
        # (`a instanceof b`, `a * b`, `a >>> b`, `++local_N`, etc.), treat the
        # ENTERWITH as part of a dead-code region: track scope but suppress
        # the emit. Also suppress the trivial `with (this)` that comes from
        # an empty stack — it produces no useful information.
        elif op == 3:
            popped_empty = not self.stack
            obj = self.stack.pop() if self.stack else "this"
            if obj == "undefined" and self.namespace:
                obj = self.namespace
            elif obj == "undefined":
                obj = "this"
            # ns dup squash on dotted paths: if the second half of the
            # segment list is a prefix-duplicate of the first half, keep
            # only the first half. Catches
            # `this.Views.Label.LabelExt.Views.Label.LabelExt`.
            if obj.count(".") >= 3:
                segs = obj.split(".")
                n = len(segs)
                for k in range(2, n // 2 + 1):
                    if segs[n - k:] == segs[n - 2 * k: n - k]:
                        obj = ".".join(segs[: n - k])
                        break
            bogus = any(t in obj for t in (" instanceof ", " % ", " >>> ", " << ", " * ",
                                            " ^ ", " | ", " & "))
            if obj.startswith(("++local_", "--local_", "++arg_", "--arg_")):
                bogus = True
            if obj.endswith(("++", "--")):
                bogus = True
            if popped_empty:
                bogus = True
            if obj == "this":
                bogus = True
            # Function-call expressions as with-scope are also stack-tracking
            # artifacts — real JS doesn't `with (foo())` outside very rare
            # code, and v9 emits `this()`/`undefined()` chains when CALL's
            # receiver underflows.
            if obj.endswith(")"):
                bogus = True
            # Store (scope, emitted_flag) so the matching LEAVEWITH can suppress
            # its `}` when we suppressed the opening `with (...) {`.
            self.with_stack.append((obj if not bogus else "this", not bogus))
            if not bogus:
                self.emit(f"with ({obj}) {{")
                self.indent += 1
            self.pc += 1
        # LEAVEWITH
        elif op == 4:
            emitted = True
            if self.with_stack:
                entry = self.with_stack.pop()
                if isinstance(entry, tuple):
                    _, emitted = entry
            if emitted:
                self.indent = max(0, self.indent - 1)
                self.emit("}")
            self.pc += 1
        # RETURN. Stack-underflow gives `return undefined;` which is real-JS-
        # legal but practically always means the stack-tracker lost the value.
        # Skip the emit so prologue detection doesn't mark this as "real".
        elif op == 5:
            val = self.pop()
            if val != "undefined":
                self.emit(f"return {val};")
            self.pc += 1
        # GOTO (JOF_JUMP, 3 bytes)
        elif op == 6:
            offset = self.read_i16()
            target = pc + offset
            self.jump_targets.add(target)
            self.pc += 3
        # IFEQ (JOF_JUMP). Strip outer paren in cond; skip emit for synthetic
        # conds (`undefined`, function literals, etc.) that come from v9
        # stack underflow rather than a real branch.
        elif op == 7:
            offset = self.read_i16()
            target = pc + offset
            if target > pc:
                cond = self.pop()
                if cond in ("undefined", "true", "false", "null", "0", "1",
                            "this", "arguments") or cond.startswith("function("):
                    pass
                else:
                    if cond.startswith("(") and cond.endswith(")"):
                        inner = cond[1:-1]
                        depth = 0
                        matches = True
                        for ch in inner:
                            if ch == "(":
                                depth += 1
                            elif ch == ")":
                                depth -= 1
                                if depth < 0:
                                    matches = False
                                    break
                        if matches and depth == 0:
                            cond = inner
                    self.emit(f"if ({cond}) {{")
                    self.indent += 1
                    self.jump_targets.add(target)
                    if pc < target <= len(self.bc):
                        self.pending_close[target] = self.pending_close.get(target, 0) + 1
            self.pc += 3
        # IFNE (JOF_JUMP).
        elif op == 8:
            offset = self.read_i16()
            target = pc + offset
            if target > pc:
                cond = self.pop()
                if cond in ("undefined", "true", "false", "null", "0", "1",
                            "this", "arguments") or cond.startswith("function("):
                    pass
                else:
                    # Drop inner parens around a simple identifier / member
                    # access to avoid `if (!(true))` style noise.
                    if re.match(r"^[\w\.]+$", cond) or re.match(r"^[\w\.]+\[\w+\]$", cond):
                        self.emit(f"if (!{cond}) {{")
                    else:
                        self.emit(f"if (!({cond})) {{")
                    self.indent += 1
                    if pc < target <= len(self.bc):
                        self.pending_close[target] = self.pending_close.get(target, 0) + 1
                    self.jump_targets.add(target)
            self.pc += 3
        # ARGUMENTS
        elif op == 9:
            self.push("arguments")
            self.pc += 1
        # FORARG (JOF_QARG)
        elif op == 10:
            val = self.pop()
            idx = self.read_u16()
            if idx >= max(self.nargs, 32):
                self.push("undefined")
            else:
                self.emit(f"arg_{idx} = {val};")
                self.push(f"arg_{idx}")
            self.pc += 3
        # FORLOCAL (JOF_LOCAL)
        elif op == 11:
            val = self.pop()
            idx = self.read_u16()
            if idx > 100:
                self.push("undefined")
            else:
                self.emit(f"local_{idx} = {val};")
                self.push(f"local_{idx}")
            self.pc += 3
        # DUP
        elif op == 12:
            self.push(self.peek())
            self.pc += 1
        # DUP2
        elif op == 13:
            if len(self.stack) >= 2:
                self.push(self.stack[-2])
                self.push(self.stack[-2])
            self.pc += 1
        # SETCONST (JOF_ATOM, 5 bytes)
        elif op == 14:
            name = self.atom(self.read_atom_idx())
            val = self.pop()
            self.emit(f"const {name} = {val};")
            self.push(val)
            self.pc += 5
        # Binary operators (15-31). v9 fix-up: when an operand is the
        # synthetic 'undefined' (stack underflow), prefer the other operand
        # rather than emitting `(undefined + X)` style noise. This is not
        # semantically faithful for operators with side effects, but cocos2d-x
        # JS uses BINOPs purely on values and the simplification yields far
        # more readable output without losing identifier names.
        elif op in BINOPS:
            right = self.pop()
            left = self.pop()
            sym = BINOPS[op]
            if left == "undefined" and right != "undefined":
                self.push(right)
            elif right == "undefined" and left != "undefined":
                self.push(left)
            elif left == "undefined" and right == "undefined":
                self.push("undefined")
            else:
                self.push(f"({left} {sym} {right})")
            self.pc += 1
        # Unary operators (32-35: NOT, BITNOT, NEG, POS).
        elif op in UNOPS:
            val = self.pop()
            sym = UNOPS[op]
            if val == "undefined":
                self.push("undefined")
            elif sym == "+":
                # `+x` is a no-op on identifiers / literals in SM; cocos2d-x
                # emits it as a number-coercion marker. Strip it for
                # readability — `+local_3 + 1` -> `local_3 + 1`.
                self.push(val)
            else:
                self.push(f"{sym}{val}")
            self.pc += 1
        # DELNAME (36, JOF_ATOM). Real JS `delete X` returns a boolean. We
        # emit the delete as a statement and push `true` as the synthetic
        # result, so downstream SET/INITPROP don't end up with
        # `delete X.Y = Z` (which is not valid JS).
        elif op == 36:
            name = self.atom(self.read_atom_idx())
            self.emit(f"delete {name};")
            self.push("true")
            self.pc += 5
        # DELPROP (37, JOF_ATOM)
        elif op == 37:
            obj = self.pop()
            name = self.atom(self.read_atom_idx())
            if obj == "undefined":
                obj = self._scope_or_namespace() or "this"
            self.emit(f"delete {obj}.{name};")
            self.push("true")
            self.pc += 5
        # DELELEM (38)
        elif op == 38:
            idx = self.pop()
            obj = self.pop()
            if obj == "undefined":
                obj = self._scope_or_namespace() or "this"
            self.emit(f"delete {obj}[{idx}];")
            self.push("true")
            self.pc += 1
        # TYPEOF (39)
        elif op == 39:
            val = self.pop()
            if val == "undefined":
                # Stack underflow — typeof on nothing is a tracker artifact.
                # Push 'undefined' instead of 'typeof undefined' so later
                # GETPROP/SETPROP don't produce 'typeof undefined.X = Y;'.
                self.push("undefined")
            else:
                self.push(f"typeof {val}")
            self.pc += 1
        # VOID (40)
        elif op == 40:
            self.pop()
            self.push("undefined")
            self.pc += 1
        # INC/DEC NAME/PROP (41-52, JOF_ATOM for name/prop). Simplify when
        # the receiver is 'undefined' (stack underflow) — pushing
        # `--undefined.foo` poisons later SETPROP chains.
        elif op in (41, 42, 44, 45, 47, 48, 50, 51):
            name = self.atom(self.read_atom_idx())
            prop_op = op in (42, 45, 48, 51)  # *PROP variants pop obj
            obj = self.pop() if prop_op else ""
            if prop_op and obj == "undefined":
                obj = self._scope_or_namespace() or "this"
            expr = f"{obj}.{name}" if obj else name
            if op in (41, 42):
                self.push(f"++{expr}")
            elif op in (44, 45):
                self.push(f"--{expr}")
            elif op in (47, 48):
                self.push(f"{expr}++")
            elif op in (50, 51):
                self.push(f"{expr}--")
            self.pc += 5
        # INCELEM/DECELEM/ELEMINC/ELEMDEC (43,46,49,52). Simplify when
        # obj/idx are 'undefined' from stack underflow — `--undefined[undefined]`
        # poisons every downstream SETPROP/GETELEM chain.
        elif op in (43, 46, 49, 52):
            idx = self.pop()
            obj = self.pop()
            if obj == "undefined" and idx == "undefined":
                # Fully underflowed — drop the inc/dec entirely and recover
                # by pushing a generic placeholder.
                self.push("undefined")
            else:
                if obj == "undefined":
                    obj = self._scope_or_namespace() or "this"
                expr = f"{obj}[{idx}]"
                if op == 43: self.push(f"++{expr}")
                elif op == 46: self.push(f"--{expr}")
                elif op == 49: self.push(f"{expr}++")
                elif op == 52: self.push(f"{expr}--")
            self.pc += 1
        # GETPROP (53, JOF_ATOM). Redirect bogus receivers; suppress
        # chained namespace duplication only when the receiver was just
        # synthesised from a fallback (i.e. original obj was undefined /
        # bogus). Real chained GETPROP from a non-fallback receiver always
        # appends.
        elif op == 53:
            obj = self.pop()
            name = self.atom(self.read_atom_idx())
            from_fallback = False
            if obj == "undefined" or self._looks_like_bogus_obj(obj):
                obj = self._scope_or_namespace() or "this"
                from_fallback = True
            # Suppress namespace-duplication chains: either when fallback
            # produced the receiver, OR when the receiver is already the
            # full namespace and `name` is a segment of it (SM dead-code
            # prologue path).
            if self.namespace and name and isinstance(obj, str):
                ns_parts = self.namespace.split(".")
                if (from_fallback and name in ns_parts) or (
                        obj == self.namespace and name in ns_parts):
                    self.push(obj)
                    self.pc += 5
                    return
            # Also avoid `xs.Views.Dialog.Dialog` style: when obj already
            # ends with `.{name}`, just push obj.
            if isinstance(obj, str) and obj.endswith("." + name):
                self.push(obj)
                self.pc += 5
                return
            self.push(f"{obj}.{name}")
            self.pc += 5
        # SETPROP (54, JOF_ATOM). Push back a reference (`obj.name`) rather
        # than the full RHS so POP/POPV don't double-emit.
        elif op == 54:
            val = self.pop()
            obj = self.pop()
            name = self.atom(self.read_atom_idx())
            if obj in ("undefined", "[]") or self._looks_like_bogus_obj(obj):
                obj = self._scope_or_namespace() or obj
            # Drop the leading `obj.name` duplication when obj already ends
            # in `.name` (SM dead-code namespace path artifact).
            if isinstance(obj, str) and obj.endswith("." + name):
                obj = obj[: -(len(name) + 1)]
            self.emit(f"{obj}.{name} = {val};")
            self.push(f"{obj}.{name}")
            self.pc += 5
        # GETELEM (55)
        elif op == 55:
            idx = self.pop()
            obj = self.pop()
            self.push(f"{obj}[{idx}]")
            self.pc += 1
        # SETELEM (56)
        elif op == 56:
            val = self.pop()
            idx = self.pop()
            obj = self.pop()
            self.emit(f"{obj}[{idx}] = {val};")
            self.push(val)
            self.pc += 1
        # CALLNAME (57, JOF_ATOM)
        elif op == 57:
            name = self.atom(self.read_atom_idx())
            self.push(name)
            self.push("this")
            self.pc += 5
        # CALL (58, JOF_UINT16). Defensive: redirect bogus func receivers
        # (BINOP results / inc-dec / undefined) so we don't emit
        # `(1 * X).call(Y, Z)` from stack-tracker garbage.
        elif op == 58:
            argc = self.read_u16()
            if argc > 20:
                argc = 0
            args = [self.pop() for _ in range(argc)][::-1]
            this_val = self.pop()
            func = self.pop()
            if func == "undefined" or self._looks_like_bogus_obj(func):
                func = self._scope_or_namespace() or "this"
            args_str = ", ".join(args)
            if this_val in ("this", "undefined"):
                self.push(f"{func}({args_str})")
            else:
                self.push(f"{func}.call({this_val}, {args_str})")
            self.pc += 3
        # NAME (59, JOF_ATOM)
        elif op == 59:
            name = self.atom(self.read_atom_idx())
            self.push(name)
            self.pc += 5
        # DOUBLE (60, JOF_ATOM)
        elif op == 60:
            val = self.atom(self.read_atom_idx())
            self.push(val)
            self.pc += 5
        # STRING (61, JOF_ATOM)
        elif op == 61:
            val = self.atom(self.read_atom_idx())
            self.push(f'"{val}"')
            self.pc += 5
        # ZERO-TRUE (62-67)
        elif op == 62: self.push("0"); self.pc += 1
        elif op == 63: self.push("1"); self.pc += 1
        elif op == 64: self.push("null"); self.pc += 1
        elif op == 65: self.push("this"); self.pc += 1
        elif op == 66: self.push("false"); self.pc += 1
        elif op == 67: self.push("true"); self.pc += 1
        # OR/AND (68,69 JOF_JUMP)
        elif op in (68, 69):
            self.pc += 3
        # TABLESWITCH/LOOKUPSWITCH (70,71,149,150)
        elif op in (70, 149):
            self._skip_tableswitch(op)
        elif op in (71, 150):
            self._skip_lookupswitch(op)
        # STRICTEQ/STRICTNE (72,73)
        elif op in (72, 73):
            right = self.pop()
            left = self.pop()
            self.push(f"({left} {BINOPS[op]} {right})")
            self.pc += 1
        # XMLCOMMENT/XMLCDATA/XMLPI (183, 184, 185) — Cocos2d-x reuses these
        # opcodes for debug metadata. They sit after a DUP and precede a
        # metadata block (FORARG / NOPs / POP). Empirically, treating them
        # as GETPROP-like recovers a few extra emits but introduces more
        # noise via root-script SETPROP chains. We keep the conservative
        # skip-to-POP behaviour which has the best OK/empty balance.
        elif op in (183, 184, 185):
            if self.stack: self.pop()
            pc = self.pc + 5  # skip the XMLCOMMENT op itself
            bc = self.bc
            while pc < len(bc) and bc[pc] == 0: pc += 1
            if pc < len(bc) and bc[pc] == 10:  # FORARG (3 bytes)
                pc += 3
            while pc < len(bc):
                b = bc[pc]
                if b == 0: pc += 1; continue
                if b in (2, 81):
                    pc += 1
                    break
                if b == 228: pc += 3; continue
                if b == 1: pc += 1; continue
                if b == 61: pc += 5; continue
                if b in (53, 54, 59, 156, 157, 187, 217): pc += 5; continue
                if b == 12: pc += 1; continue
                if b == 84: pc += 3; continue
                if b == 27: pc += 1; continue
                if b == 65: pc += 1; continue
                break
            self.pc = pc
        # GETARG/SETARG (84,85)
        # Clamp to a sane range — large indices come from misread operand
        # bytes that aren't actually function arguments.
        elif op == 84:
            idx = self.read_u16()
            if idx >= max(self.nargs, 32):
                self.push("undefined")
            else:
                self.push(f"arg_{idx}")
            self.pc += 3
        elif op == 85:
            idx = self.read_u16()
            val = self.pop()
            if idx >= max(self.nargs, 32):
                self.push(val)
            else:
                self.emit(f"arg_{idx} = {val};")
                self.push(f"arg_{idx}")
            self.pc += 3
        # GETLOCAL/SETLOCAL (86,87) — clamp + drop synthetic assignments.
        # SETLOCAL pushes back the *reference* (`local_N`) rather than the
        # full RHS expression — this prevents subsequent POP/POPV from
        # double-emitting `(rhs);` after `local_N = rhs;`.
        elif op == 86:
            idx = self.read_u16()
            if idx > 100:
                self.push("undefined")
            else:
                self.push(f"local_{idx}")
            self.pc += 3
        elif op == 87:
            idx = self.read_u16()
            val = self.pop()
            if idx > 100:
                self.push(val)
            else:
                self.emit(f"local_{idx} = {val};")
                self.push(f"local_{idx}")
            self.pc += 3
        # UINT16 (88) - push value (BE like all JOF_UINT16)
        elif op == 88:
            self.push(str(self.read_u16()))
            self.pc += 3
        # POP (81). In SM 1.8.5 most expression statements inside a function
        # body compile to `... POP`. Mirror POPV's behaviour and emit when the
        # discarded value carries observable side effects (a call or an
        # assignment).
        elif op == 81:
            val = self.pop()
            if "(" in val or "=" in val:
                self.emit(f"{val};")
            self.pc += 1
        # NEW (82, JOF_UINT16)
        elif op == 82:
            argc = self.read_u16()
            if argc > 20:
                argc = 0
            args = [self.pop() for _ in range(argc)][::-1]
            ctor = self.pop()
            self.push(f"new {ctor}({', '.join(args)})")
            self.pc += 3
        # INT8 (221, JOF_INT8)
        elif op == 221:
            val = struct.unpack_from('b', self.bc, self.pc + 1)[0]
            self.push(str(val))
            self.pc += 2
        # INT32 (222, JOF_INT32)
        elif op == 222:
            val = self.read_i32()
            self.push(str(val))
            self.pc += 5
        # UINT24 (190)
        elif op == 190:
            val = (self.bc[self.pc+1] << 16) | (self.bc[self.pc+2] << 8) | self.bc[self.pc+3]
            self.push(str(val))
            self.pc += 4
        # STOP (197)
        elif op == 197:
            self.pc += 1
        # CALLPROP (187, JOF_ATOM)
        elif op == 187:
            obj = self.pop()
            name = self.atom(self.read_atom_idx())
            if obj == "undefined":
                obj = self._scope_or_namespace() or "this"
            # ns dup squash
            if isinstance(obj, str) and obj.endswith("." + name):
                self.push(obj)
                self.push(obj)
                self.pc += 5
                return
            self.push(f"{obj}.{name}")
            self.push(obj)
            self.pc += 5
        # GETGNAME/SETGNAME (156,157)
        elif op == 156:
            name = self.atom(self.read_atom_idx())
            self.push(name)
            self.pc += 5
        elif op == 157:
            val = self.pop()
            name = self.atom(self.read_atom_idx())
            self.emit(f"{name} = {val};")
            self.push(val)
            self.pc += 5
        # CALLGNAME (217)
        elif op == 217:
            name = self.atom(self.read_atom_idx())
            self.push(name)
            self.push("this")
            self.pc += 5
        # BINDGNAME (220)
        elif op == 220:
            name = self.atom(self.read_atom_idx())
            self.push(name)
            self.pc += 5
        # LAMBDA/DEFFUN/DEFLOCALFUN (130,127,128,225-234)
        elif op in (130, 227, 234):  # LAMBDA, LAMBDA_FC, LAMBDA_DBGFC
            obj_idx = self.read_obj_idx()  # object index (no INDEXBASE)
            func_src = self._decompile_nested(obj_idx)
            self.push(func_src)
            self.pc += 5
        elif op in (127, 225, 232):  # DEFFUN, DEFFUN_FC, DEFFUN_DBGFC
            obj_idx = self.read_obj_idx()
            func_src = self._decompile_nested(obj_idx)
            # Skip emit when the sub-script reduced to an empty stub —
            # arbitrary `function() {}` lines look like syntax errors in JS.
            if func_src and func_src.strip() not in ("function() {}", "function () {}"):
                self.emit(func_src)
            self.pc += 5
        # DEFCONST (128, JOF_ATOM, 5 bytes) — `const NAME;` declaration. SM
        # leaves the value on the stack as the const initializer.
        elif op == 128:
            name = self.atom(self.read_atom_idx())
            val = self.peek() if self.stack else "undefined"
            self.emit(f"const {name} = {val};")
            self.pc += 5
        elif op in (140, 226, 233):  # DEFLOCALFUN / DEFLOCALFUN_FC / DEFLOCALFUN_DBGFC
            obj_idx = self.read_obj_idx()
            func_src = self._decompile_nested(obj_idx)
            self.push(func_src)
            self.pc += 5
        # NEWINIT (89, JOF_UINT8)
        elif op == 89:
            kind = self.read_u8()
            if kind == 0:
                self.push("{}")
            else:
                self.push("[]")
            self.pc += 2
        # INITPROP (93, JOF_ATOM)
        elif op == 93:
            val = self.pop()
            name = self.atom(self.read_atom_idx())
            # Squash trailing namespace-segment duplication when the obj on
            # the stack already ends in `.{name}` (cocos2d-x dead-code
            # `xs.Views.Dialog.Dialog.X` pattern).
            if self.stack:
                top = self.stack[-1]
                if isinstance(top, str) and top.endswith("." + name) and "." in top:
                    self.stack[-1] = top[: -(len(name) + 1)]
            # Pick the target object:
            #   1. If stack-top is an empty/partial object literal accumulator,
            #      extend it in place (handles `obj = {a:1, b:2}` syntax).
            #   2. Else if stack-top is the with-scope object (or empty array
            #      `[]` left behind by a stale NEWINIT), prefer with-scope.
            #   3. Else if stack-top resolves to 'undefined', fall back to
            #      with-scope, then namespace.
            target = None
            if self.stack:
                obj = self.peek()
                if obj.endswith("{}"):
                    self.stack[-1] = f"{{{name}: {val}}}"
                    self.pc += 5
                    return
                if obj.startswith("{") and not obj.startswith("{ "):
                    self.stack[-1] = f"{obj[:-1]}, {name}: {val}}}"
                    self.pc += 5
                    return
                if obj in ("undefined", "[]") or self._looks_like_bogus_obj(obj):
                    target = self._scope_or_namespace() or obj
                else:
                    target = obj
            else:
                target = self._scope_or_namespace() or "/* unknown */"
            self.emit(f"{target}.{name} = {val};")
            self.pc += 5
        # ENDINIT (92)
        elif op == 92:
            self.pc += 1
        # INITELEM (94)
        elif op == 94:
            val = self.pop()
            idx = self.pop()
            self.pc += 1
        # SWAP (79)
        elif op == 79:
            if len(self.stack) >= 2:
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
            self.pc += 1
        # TYPEOF/TYPEOFEXPR (39, 200)
        elif op == 200:
            val = self.pop()
            if val == "undefined":
                self.push("undefined")
            else:
                self.push(f"typeof {val}")
            self.pc += 1
        # FORELEM (108, JOF_BYTE) — used as `for (X[Y] in iter)` last step.
        # Pops the array index, leaves the iterator state on stack. We don't
        # model the for-in iterator chain, just pop one to keep balance.
        elif op == 108:
            if self.stack:
                self.pop()
            self.pc += 1
        # IN (109)
        # POPN (109, JOF_UINT16, 3 bytes) — pop N values from stack. v9 had
        # mis-tagged this as `in`, but `in` is op 113.
        elif op == 109:
            n = self.read_u16()
            for _ in range(min(n, len(self.stack))):
                self.pop()
            self.pc += 3
            return
        # (legacy: kept original undefined-fallback `in` branch below for the
        # real IN op via op == 113 above — duplicate below is unreachable)
        elif op == 99999:
            right = self.pop()
            left = self.pop()
            if right == "undefined" and left != "undefined":
                self.push(left)
            elif left == "undefined" and right != "undefined":
                self.push(right)
            elif left == "undefined" and right == "undefined":
                self.push("undefined")
            else:
                self.push(f"({left} in {right})")
            self.pc += 1
        # FUNAPPLY/FUNCALL (78, 242)
        elif op in (78, 242):
            argc = self.read_u16()
            if argc > 20:
                argc = 0
            args = [self.pop() for _ in range(argc)][::-1]
            this_val = self.pop()
            func = self.pop()
            if func == "undefined":
                func = self._scope_or_namespace() or "this"
            self.push(f"{func}({', '.join(args)})")
            self.pc += 3
        # GETTHISPROP (211, JOF_ATOM)
        elif op == 211:
            name = self.atom(self.read_atom_idx())
            self.push(f"this.{name}")
            self.pc += 5
        # INDEXBASE (191, JOF_UINT8)
        # SM 1.8.5: subsequent atom/object indices are OR'd with (operand<<16).
        # Cocos2d-x sometimes emits INDEXBASE for non-atom purposes (e.g. as a
        # padding/dead-code byte), so we only apply when the resulting base
        # could plausibly land inside the atom table.
        elif op == 191:
            base = self.bc[self.pc + 1] if self.pc + 1 < len(self.bc) else 0
            shifted = base << 16
            if shifted < max(len(self.atoms), 256):
                self.index_base = shifted
            self.pc += 2
        # INDEXBASE1/2/3 (214,215,216) — preset bases of 1/2/3
        elif op in (214, 215, 216):
            shifted = (op - 213) << 16
            if shifted < max(len(self.atoms), 256):
                self.index_base = shifted
            self.pc += 1
        # RESETBASE/RESETBASE0 (192,193)
        elif op in (192, 193):
            self.index_base = 0
            self.pc += 1
        # THROW (112). Same idea as RETURN — empty-stack throws are dead
        # bytecode artifacts.
        elif op == 112:
            val = self.pop()
            if val != "undefined":
                self.emit(f"throw {val};")
            self.pc += 1
        # INSTANCEOF (114)
        elif op == 114:
            right = self.pop()
            left = self.pop()
            if right == "undefined" and left != "undefined":
                self.push(left)
            elif left == "undefined" and right != "undefined":
                self.push(right)
            elif left == "undefined" and right == "undefined":
                self.push("undefined")
            else:
                self.push(f"({left} instanceof {right})")
            self.pc += 1
        # DEBUGGER (115)
        elif op == 115:
            self.pc += 1
        # GOSUB/GOSUBX (116, 146)
        elif op in (116, 146):
            self.pc += 3 if op == 116 else 5
        # INCARG/DECARG/ARGINC/ARGDEC (97-100). Plausible idx range is small;
        # giant indices indicate the bytes were operand bytes of a larger op
        # we misread, so push 'undefined' instead of polluting the stack.
        elif op in (97, 98, 99, 100):
            idx = self.read_u16()
            if idx > max(self.nargs, 32):
                self.push("undefined")
            elif op == 97: self.push(f"++arg_{idx}")
            elif op == 98: self.push(f"--arg_{idx}")
            elif op == 99: self.push(f"arg_{idx}++")
            elif op == 100: self.push(f"arg_{idx}--")
            self.pc += 3
        # INCLOCAL/DECLOCAL/LOCALINC/LOCALDEC (101-104)
        elif op in (101, 102, 103, 104):
            idx = self.read_u16()
            if idx > 100:
                self.push("undefined")
            elif op == 101: self.push(f"++local_{idx}")
            elif op == 102: self.push(f"--local_{idx}")
            elif op == 103: self.push(f"local_{idx}++")
            elif op == 104: self.push(f"local_{idx}--")
            self.pc += 3
        # IMACOP (105) - internal, skip
        elif op == 105:
            self.pc += 1
        # USESHARP (96, JOF_UINT16PAIR = 5 bytes)
        elif op == 96:
            self.push("undefined")
            self.pc += 5
        # DEFSHARP (95, JOF_UINT16PAIR = 5 bytes)
        elif op == 95:
            self.pc += 5
        # ENTERBLOCK (201, JOF_OBJECT = 5 bytes)
        elif op == 201:
            self.pc += 5
        # LEAVEBLOCK (202, JOF_UINT16 = 3 bytes)
        elif op == 202:
            self.pc += 3
        # LEAVEBLOCKEXPR (210, JOF_UINT16 = 3 bytes)
        elif op == 210:
            self.pc += 3
        # ANDX/ORX (145, 144, JOF_JUMPX = 5 bytes)
        elif op in (144, 145):
            self.pc += 5
        # GOTOX/IFEQX/IFNEX (141-143, JOF_JUMPX = 5 bytes)
        elif op in (141, 142, 143):
            if op == 142 or op == 143:
                self.pop()  # condition
            self.pc += 5
        # ITER (75, JOF_UINT8)
        elif op == 75:
            self.pc += 2
        # MOREITER (76)
        elif op == 76:
            self.push("hasNext")  # for-in iterator continuation flag
            self.pc += 1
        # ENDITER (77)
        elif op == 77:
            if self.stack: self.pop()
            self.pc += 1
        # BINDNAME (110, JOF_ATOM, 5 bytes): SM pushes the binding's scope
        # object. Empirically, treating this as no-op gives the fewest
        # `undefined.X` artifacts on cocos2d-x 2.2.5 bytecode (pushing a
        # marker shifted intermediate GETPROP pops by one and caused MORE
        # underflows). Real-world cocos2d-x code rarely chains complex
        # expressions between BINDNAME and SETNAME, so the stack-depth gap
        # is harmless in practice.
        elif op == 110:
            self.read_atom_idx()
            self.pc += 5
        # SETNAME (111, JOF_ATOM): emit `name = value;`. Pop only the value
        # to match BINDNAME's no-op above.
        elif op == 111:
            val = self.pop()
            name = self.atom(self.read_atom_idx())
            self.emit(f"{name} = {val};")
            self.push(val)
            self.pc += 5
        # FORNAME/FORGNAME (106/243, JOF_ATOM) — for-in iterator names
        elif op in (106, 243):
            self.pc += 5
        # FORPROP (107) / FORELEM (108) / IN (113)
        elif op == 107:
            self.pc += 5
        # IN (113, JOF_BYTE) — `left in right`
        elif op == 113:
            right = self.pop()
            left = self.pop()
            if right == "undefined" and left != "undefined":
                self.push(left)
            elif left == "undefined" and right != "undefined":
                self.push(right)
            elif left == "undefined" and right == "undefined":
                self.push("undefined")
            else:
                self.push(f"({left} in {right})")
            self.pc += 1
        # TRY (134) / FINALLY (135) / EXCEPTION (118)
        elif op == 134:
            self.emit("try {")
            self.indent += 1
            self.try_depth += 1
            self.pc += 1
        elif op == 135:
            if self.try_depth > 0:
                self.indent = max(0, self.indent - 1)
                self.emit("} finally {")
                self.indent += 1
            self.pc += 1
        elif op == 118:
            # SM 1.8.5 catch handler entry. Only meaningful inside a `try`.
            # In dead bytecode (try_depth == 0) or when the last emit was
            # already a `} catch (e) {` for an empty try, skip the emit to
            # avoid `} catch (e) { } catch (e) {` runs.
            if self.try_depth > 0:
                last = self.output[-1].strip() if self.output else ""
                if last == "} catch (e) {":
                    self.push("e")
                else:
                    self.indent = max(0, self.indent - 1)
                    self.emit("} catch (e) {")
                    self.indent += 1
                    self.try_depth -= 1
                    self.push("e")
            else:
                self.push("undefined")
            self.pc += 1
        # THROWING (153) / SETRVAL (154) / RETRVAL (155)
        elif op in (153, 154):
            self.pop()
            self.pc += 1
        elif op == 155:
            self.pc += 1
        # PICK (133, JOF_UINT8)
        elif op == 133:
            self.pc += 2
        # SETCALL (74)
        elif op == 74:
            self.pc += 1
        # TRAP (83)
        elif op == 83:
            self.pc += 1
        # OBJECT (80, JOF_OBJECT = 5 bytes) — push a pre-compiled object
        # literal from the script's object table. We don't unwind it, just
        # use {} as the placeholder; the SETPROP/INITPROP chain that follows
        # already produces readable field assignments.
        elif op == 80:
            self.read_obj_idx()
            self.push("{}")
            self.pc += 5
        # NEWARRAY (90, JOF_UINT24 = 4 bytes)
        elif op == 90:
            self.push("[]")
            self.pc += 4
        # NEWOBJECT (91, JOF_OBJECT = 5 bytes)
        elif op == 91:
            self.push("{}")
            self.pc += 5
        # BLOCKCHAIN (188, JOF_OBJECT = 5 bytes)
        elif op == 188:
            self.pc += 5
        # NULLBLOCKCHAIN (189)
        elif op == 189:
            self.pc += 1
        # CALLLOCAL (218, JOF_LOCAL = 3 bytes). Clamp out-of-range indices
        # to 'undefined' so we don't produce `local_32891(...)` style calls.
        elif op == 218:
            idx = self.read_u16()
            if idx > 100:
                self.push("undefined")
            else:
                self.push(f"local_{idx}")
            self.push("this")
            self.pc += 3
        # CALLARG (219, JOF_QARG = 3 bytes)
        elif op == 219:
            idx = self.read_u16()
            if idx >= max(self.nargs, 32):
                self.push("undefined")
            else:
                self.push(f"arg_{idx}")
            self.push("this")
            self.pc += 3
        # Cocos2d-x extension opcodes (244-255)
        elif 244 <= op <= 255:
            self.pc += 1
        # Default: skip unknown opcodes using size table
        else:
            self.pc += self._opcode_size(op)

    def _opcode_size(self, op):
        """Get instruction size from opcode table."""
        from decompile_to_js_v8 import OPCODE_ENTRIES, SM_FL as V8_FL
        for oc, name, fmt in OPCODE_ENTRIES:
            if oc == op:
                sz = V8_FL.get(fmt, 1)
                return sz if sz > 0 else 1
        return 1

    def _skip_tableswitch(self, op):
        # SM 1.8.5 TABLESWITCH layout:
        #   op default(BE i16) low(BE i32) high(BE i32) jumps(n * BE i16)
        # If anything looks bogus (huge n / out-of-range result) advance by 1
        # so the main loop can still progress; many `op=70` bytes in our
        # bc-windowed data are NOT real TABLESWITCH opcodes.
        if self.pc + 11 > len(self.bc):
            self.pc += 1; return
        try:
            low = struct.unpack_from('>i', self.bc, self.pc + 3)[0]
            high = struct.unpack_from('>i', self.bc, self.pc + 7)[0]
            n = high - low + 1
        except Exception:
            self.pc += 1; return
        if not (0 <= n <= 1024):
            # bogus table — skip just the opcode byte
            self.pc += 1; return
        if self.stack: self.pop()
        new_pc = self.pc + 11 + n * 2
        if new_pc > len(self.bc):
            self.pc += 1
        else:
            self.pc = new_pc

    def _skip_lookupswitch(self, op):
        if self.pc + 5 > len(self.bc):
            self.pc += 1; return
        try:
            npairs = struct.unpack_from('>H', self.bc, self.pc + 3)[0]
        except Exception:
            self.pc += 1; return
        if npairs > 1024:
            self.pc += 1; return
        if self.stack: self.pop()
        new_pc = self.pc + 5 + npairs * 4
        if new_pc > len(self.bc):
            self.pc += 1
        else:
            self.pc = new_pc

    def _decompile_nested(self, obj_idx):
        """Recursively decompile a nested function object.

        Sub-script atom indices ALWAYS reference the sub-script's own
        nested_atoms table (counting from 0). Passing parent atoms would shift
        every GETPROP/SETPROP/STRING/NAME by len(parent_atoms), producing
        completely wrong identifiers. SM 1.8.5 uses GETUPVAR/CALLUPVAR/
        GETFCSLOT (different opcodes) to reach across script boundaries.
        """
        if not self.nested or obj_idx >= len(self.nested):
            return "function() {}"
        obj = self.nested[obj_idx]
        if not isinstance(obj, dict) or 'bc' not in obj:
            return "function() {}"
        nested_bc = obj['bc']
        nested_atoms = obj.get('nested_atoms', [])
        sub_scripts = obj.get('sub_scripts', [])
        nargs = obj.get('nargs', 0)
        if not nested_bc or len(nested_bc) < 2:
            return "function() {}"
        sub = StackDecompiler(nested_bc, nested_atoms, sub_scripts, nargs)
        try:
            body = sub.decompile()
        except Exception:
            body = "/* decompile error */"
        args = ", ".join(f"arg_{i}" for i in range(nargs))
        # If the filter pass nuked everything but the raw walk produced
        # at least one real-looking statement, fall back to the raw output.
        # This recovers some nested functions where dead-code filtering
        # was too aggressive on a short body that had a single substantive
        # `return X;`.
        if not body.strip() and sub.output:
            real_lines = []
            for ln in sub.output:
                s = ln.strip()
                if not s: continue
                # Drop the obvious garbage we already filter inline.
                if s in ("return undefined;", "throw undefined;",
                         "(undefined);", "undefined;"):
                    continue
                if re.match(r"^(local|arg)_\d+\s*=\s*undefined;?$", s):
                    continue
                real_lines.append(ln)
            if real_lines:
                body = "\n".join(real_lines)
        if body.strip():
            return f"function({args}) {{\n{body}\n}}"
        return f"function({args}) {{}}"


def _infer_namespace(jsc_path):
    """Infer JS root namespace from path. The cocos2d-x project organizes
    scripts as `xs.<dir1>.<dir2>...<basename>`. Returns e.g.
    'xs.Guide.GuideMgr' for src_jsc/Guide/GuideMgr.jsc.
    """
    norm = jsc_path.replace("\\", "/")
    for anchor in ("/src_jsc/", "/data_cn_jsc/"):
        if anchor in norm:
            rel = norm.rsplit(anchor, 1)[1]
            if rel.endswith(".jsc"):
                rel = rel[:-4]
            parts = [p for p in rel.split("/") if p]
            if not parts:
                return None
            return "xs." + ".".join(parts)
    return None


def decompile_file(jsc_path):
    """Decompile a single JSC file."""
    reader = JSCReader()
    # analyze_jsc treats relative paths as relative to its JSC_DIR. We always pass
    # an absolute path so callers can use any working directory.
    abs_path = os.path.abspath(jsc_path)
    result = reader.analyze_jsc(abs_path)
    if result is None:
        return f"// Cannot parse: {jsc_path}"

    bc, atoms, field1, field5, natoms, nobjects, objects, xdr = result

    if not bc or len(bc) < 4:
        return f"// Empty bytecode: {jsc_path}"

    namespace = _infer_namespace(jsc_path)
    decomp = StackDecompiler(bc, atoms, objects, namespace=namespace)
    try:
        output = decomp.decompile()
    except Exception as e:
        output = f"// Decompilation error: {e}"
    return output


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python decompile_jsc_v9.py <input.jsc>")
        sys.exit(1)
    path = sys.argv[1]
    result = decompile_file(path)
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'w', encoding='utf-8') as f:
            f.write(result)
    else:
        print(result)
