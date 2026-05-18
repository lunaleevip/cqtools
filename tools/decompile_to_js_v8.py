#!/usr/bin/env python3
"""
JSC → JavaScript Decompiler v8
SM 1.8.5 (Cocos2d-x dialect) bytecode-aware decompiler.

Changes from v7:
  - _is_jsb_binding() rewritten to use walk-completeness as primary signal,
    removing false-positive Pattern 3 that incorrectly flagged NOP+GETPROP
    sequences (e.g. xs.Cfg.<X>...) as JSB inline data. This unblocks decompile
    for files like Tools/Net.jsc, Cfg/Url.jsc, Profile/UserCfg.jsc and
    Scene/Login/LoginScene_BfSdk.jsc, which all start with NOP(0x00) GETPROP(0x35).
  - Operand sizes kept as v7-empirical (Cocos2d-x dialect: JOF_ATOM=5 etc.)
    since they produce valid disassembly for non-JSB files.
"""
import struct, os, sys, json

# Default sgscqtv paths; can be overridden via CLI args.
JSC_DIR = "D:/Coder/sgscqtv/apktool_decoded/assets/src_jsc"


def _js_string(s):
    """Format a string as a JavaScript string literal, preserving Unicode (no \\uXXXX)."""
    result = '"'
    for ch in s:
        if ch == '"':
            result += '\\"'
        elif ch == '\\':
            result += '\\\\'
        elif ch == '\n':
            result += '\\n'
        elif ch == '\r':
            result += '\\r'
        elif ch == '\t':
            result += '\\t'
        elif ord(ch) < 0x20:
            result += '\\x%02x' % ord(ch)
        else:
            result += ch
    result += '"'
    return result
JSC_DIR2 = "D:/Coder/sgscqtv/apktool_decoded/assets/data_cn_jsc"
OUT_DIR = "D:/Coder/sgscqtv/decompiled_js_v8"

# Cocos2d-x SM 1.8.5 dialect sizes (verified empirically):
# JOF_ATOM/JOF_OBJECT/JOF_REGEXP use 5-byte instructions with 1-byte index at byte 4
# (high byte of LE uint32 operand). Standard SM 1.8.5 uses 3 bytes here, but Cocos2d-x
# patched the engine to use 5 bytes for additional index space.
SM_FL = {
    'JOF_BYTE': 1, 'JOF_JUMP': 3, 'JOF_ATOM': 5, 'JOF_UINT16': 3,
    'JOF_QARG': 3, 'JOF_LOCAL': 3, 'JOF_REGEXP': 5, 'JOF_OBJECT': 5,
    'JOF_UINT24': 4, 'JOF_UINT8': 2, 'JOF_INT8': 2, 'JOF_INT32': 5,
    'JOF_JUMPX': 5, 'JOF_GLOBAL': 3, 'JOF_UINT16PAIR': 5,
    'JOF_SLOTOBJECT': 5, 'JOF_SLOTATOM': 5,
    'JOF_TABLESWITCH': -1, 'JOF_LOOKUPSWITCH': -1,
    'JOF_TABLESWITCHX': -1, 'JOF_LOOKUPSWITCHX': -1,
    'JOF_BACKPATCH': 0,
}

OPCODE_ENTRIES = [
    (0,"NOP","JOF_BYTE"),(1,"PUSH","JOF_BYTE"),(2,"POPV","JOF_BYTE"),
    (3,"ENTERWITH","JOF_BYTE"),(4,"LEAVEWITH","JOF_BYTE"),(5,"RETURN","JOF_BYTE"),
    (6,"GOTO","JOF_JUMP"),(7,"IFEQ","JOF_JUMP"),(8,"IFNE","JOF_JUMP"),
    (9,"ARGUMENTS","JOF_BYTE"),(10,"FORARG","JOF_QARG"),(11,"FORLOCAL","JOF_LOCAL"),
    (12,"DUP","JOF_BYTE"),(13,"DUP2","JOF_BYTE"),
    (14,"SETCONST","JOF_ATOM"),(15,"BITOR","JOF_BYTE"),(16,"BITXOR","JOF_BYTE"),
    (17,"BITAND","JOF_BYTE"),(18,"EQ","JOF_BYTE"),(19,"NE","JOF_BYTE"),
    (20,"LT","JOF_BYTE"),(21,"LE","JOF_BYTE"),(22,"GT","JOF_BYTE"),
    (23,"GE","JOF_BYTE"),(24,"LSH","JOF_BYTE"),(25,"RSH","JOF_BYTE"),
    (26,"URSH","JOF_BYTE"),(27,"ADD","JOF_BYTE"),(28,"SUB","JOF_BYTE"),
    (29,"MUL","JOF_BYTE"),(30,"DIV","JOF_BYTE"),(31,"MOD","JOF_BYTE"),
    (32,"NOT","JOF_BYTE"),(33,"BITNOT","JOF_BYTE"),(34,"NEG","JOF_BYTE"),
    (35,"POS","JOF_BYTE"),(36,"DELNAME","JOF_ATOM"),(37,"DELPROP","JOF_ATOM"),
    (38,"DELELEM","JOF_BYTE"),(39,"TYPEOF","JOF_BYTE"),(40,"VOID","JOF_BYTE"),
    (41,"INCNAME","JOF_ATOM"),(42,"INCPROP","JOF_ATOM"),(43,"INCELEM","JOF_BYTE"),
    (44,"DECNAME","JOF_ATOM"),(45,"DECPROP","JOF_ATOM"),(46,"DECELEM","JOF_BYTE"),
    (47,"NAMEINC","JOF_ATOM"),(48,"PROPINC","JOF_ATOM"),(49,"ELEMINC","JOF_BYTE"),
    (50,"NAMEDEC","JOF_ATOM"),(51,"PROPDEC","JOF_ATOM"),(52,"ELEMDEC","JOF_BYTE"),
    (53,"GETPROP","JOF_ATOM"),(54,"SETPROP","JOF_ATOM"),(55,"GETELEM","JOF_BYTE"),
    (56,"SETELEM","JOF_BYTE"),(57,"CALLNAME","JOF_ATOM"),
    (58,"CALL","JOF_UINT16"),(59,"NAME","JOF_ATOM"),
    (60,"DOUBLE","JOF_ATOM"),(61,"STRING","JOF_ATOM"),
    (62,"ZERO","JOF_BYTE"),(63,"ONE","JOF_BYTE"),(64,"NULL","JOF_BYTE"),
    (65,"THIS","JOF_BYTE"),(66,"FALSE","JOF_BYTE"),(67,"TRUE","JOF_BYTE"),
    (68,"OR","JOF_JUMP"),(69,"AND","JOF_JUMP"),
    (70,"TABLESWITCH","JOF_TABLESWITCH"),(71,"LOOKUPSWITCH","JOF_LOOKUPSWITCH"),
    (72,"STRICTEQ","JOF_BYTE"),(73,"STRICTNE","JOF_BYTE"),
    (74,"SETCALL","JOF_BYTE"),(75,"ITER","JOF_UINT8"),
    (76,"MOREITER","JOF_BYTE"),(77,"ENDITER","JOF_BYTE"),
    (78,"FUNAPPLY","JOF_UINT16"),(79,"SWAP","JOF_BYTE"),
    (80,"OBJECT","JOF_OBJECT"),(81,"POP","JOF_BYTE"),(82,"NEW","JOF_UINT16"),
    (83,"TRAP","JOF_BYTE"),
    (84,"GETARG","JOF_QARG"),(85,"SETARG","JOF_QARG"),
    (86,"GETLOCAL","JOF_LOCAL"),(87,"SETLOCAL","JOF_LOCAL"),
    (88,"UINT16","JOF_UINT16"),(89,"NEWINIT","JOF_UINT8"),
    (90,"NEWARRAY","JOF_UINT24"),(91,"NEWOBJECT","JOF_OBJECT"),
    (92,"ENDINIT","JOF_BYTE"),(93,"INITPROP","JOF_ATOM"),(94,"INITELEM","JOF_BYTE"),
    (95,"DEFSHARP","JOF_UINT16PAIR"),(96,"USESHARP","JOF_UINT16PAIR"),
    (97,"INCARG","JOF_QARG"),(98,"DECARG","JOF_QARG"),
    (99,"ARGINC","JOF_QARG"),(100,"ARGDEC","JOF_QARG"),
    (101,"INCLOCAL","JOF_LOCAL"),(102,"DECLOCAL","JOF_LOCAL"),
    (103,"LOCALINC","JOF_LOCAL"),(104,"LOCALDEC","JOF_LOCAL"),
    (105,"IMACOP","JOF_BYTE"),(106,"FORNAME","JOF_ATOM"),(107,"FORPROP","JOF_ATOM"),
    (108,"FORELEM","JOF_BYTE"),(109,"POPN","JOF_UINT16"),
    (110,"BINDNAME","JOF_ATOM"),(111,"SETNAME","JOF_ATOM"),
    (112,"THROW","JOF_BYTE"),(113,"IN","JOF_BYTE"),(114,"INSTANCEOF","JOF_BYTE"),
    (115,"DEBUGGER","JOF_BYTE"),(116,"GOSUB","JOF_JUMP"),(117,"RETSUB","JOF_BYTE"),
    (118,"EXCEPTION","JOF_BYTE"),(119,"LINENO","JOF_UINT16"),
    (120,"CONDSWITCH","JOF_BYTE"),(121,"CASE","JOF_JUMP"),(122,"DEFAULT","JOF_JUMP"),
    (123,"EVAL","JOF_UINT16"),(124,"ENUMELEM","JOF_BYTE"),
    (125,"GETTER","JOF_BYTE"),(126,"SETTER","JOF_BYTE"),
    (127,"DEFFUN","JOF_OBJECT"),(128,"DEFCONST","JOF_ATOM"),(129,"DEFVAR","JOF_ATOM"),
    (130,"LAMBDA","JOF_OBJECT"),(131,"CALLEE","JOF_BYTE"),
    (132,"SETLOCALPOP","JOF_LOCAL"),(133,"PICK","JOF_UINT8"),
    (134,"TRY","JOF_BYTE"),(135,"FINALLY","JOF_BYTE"),
    (136,"GETFCSLOT","JOF_UINT16"),(137,"CALLFCSLOT","JOF_UINT16"),
    (138,"ARGSUB","JOF_QARG"),(139,"ARGCNT","JOF_BYTE"),
    (140,"DEFLOCALFUN","JOF_SLOTOBJECT"),
    (141,"GOTOX","JOF_JUMPX"),(142,"IFEQX","JOF_JUMPX"),(143,"IFNEX","JOF_JUMPX"),
    (144,"ORX","JOF_JUMPX"),(145,"ANDX","JOF_JUMPX"),
    (146,"GOSUBX","JOF_JUMPX"),(147,"CASEX","JOF_JUMPX"),(148,"DEFAULTX","JOF_JUMPX"),
    (149,"TABLESWITCHX","JOF_TABLESWITCHX"),(150,"LOOKUPSWITCHX","JOF_LOOKUPSWITCHX"),
    (151,"BACKPATCH","JOF_JUMP"),(152,"BACKPATCH_POP","JOF_JUMP"),
    (153,"THROWING","JOF_BYTE"),(154,"SETRVAL","JOF_BYTE"),(155,"RETRVAL","JOF_BYTE"),
    (156,"GETGNAME","JOF_ATOM"),(157,"SETGNAME","JOF_ATOM"),
    (158,"INCGNAME","JOF_ATOM"),(159,"DECGNAME","JOF_ATOM"),
    (160,"GNAMEINC","JOF_ATOM"),(161,"GNAMEDEC","JOF_ATOM"),
    (162,"REGEXP","JOF_REGEXP"),(163,"DEFXMLNS","JOF_BYTE"),
    (164,"ANYNAME","JOF_BYTE"),(165,"QNAMEPART","JOF_ATOM"),(166,"QNAMECONST","JOF_ATOM"),
    (167,"QNAME","JOF_BYTE"),
    (168,"TOATTRNAME","JOF_BYTE"),(169,"TOATTRVAL","JOF_BYTE"),(170,"ADDATTRNAME","JOF_BYTE"),
    (171,"ADDATTRVAL","JOF_BYTE"),
    (172,"BINDXMLNAME","JOF_BYTE"),(173,"SETXMLNAME","JOF_BYTE"),
    (174,"XMLNAME","JOF_BYTE"),(175,"DESCENDANTS","JOF_BYTE"),
    (176,"FILTER","JOF_JUMP"),(177,"ENDFILTER","JOF_JUMP"),
    (178,"TOXML","JOF_BYTE"),(179,"TOXMLLIST","JOF_BYTE"),
    (180,"XMLTAGEXPR","JOF_BYTE"),(181,"XMLELTEXPR","JOF_BYTE"),
    (182,"NOTRACE","JOF_UINT16"),
    (183,"XMLCDATA","JOF_ATOM"),(184,"XMLCOMMENT","JOF_ATOM"),(185,"XMLPI","JOF_ATOM"),
    (186,"DELDESC","JOF_BYTE"),
    (187,"CALLPROP","JOF_ATOM"),
    (188,"BLOCKCHAIN","JOF_OBJECT"),(189,"NULLBLOCKCHAIN","JOF_BYTE"),
    (190,"UINT24","JOF_UINT24"),(191,"INDEXBASE","JOF_UINT8"),
    (192,"RESETBASE","JOF_BYTE"),(193,"RESETBASE0","JOF_BYTE"),
    (194,"STARTXML","JOF_BYTE"),(195,"STARTXMLEXPR","JOF_BYTE"),(196,"CALLELEM","JOF_BYTE"),
    (197,"STOP","JOF_BYTE"),
    (198,"GETXPROP","JOF_ATOM"),(199,"CALLXMLNAME","JOF_BYTE"),
    (200,"TYPEOFEXPR","JOF_BYTE"),(201,"ENTERBLOCK","JOF_OBJECT"),
    (202,"LEAVEBLOCK","JOF_UINT16"),(203,"IFPRIMTOP","JOF_JUMP"),
    (204,"PRIMTOP","JOF_INT8"),(205,"GENERATOR","JOF_BYTE"),(206,"YIELD","JOF_BYTE"),
    (207,"ARRAYPUSH","JOF_LOCAL"),(208,"GETFUNNS","JOF_BYTE"),
    (209,"ENUMCONSTELEM","JOF_BYTE"),(210,"LEAVEBLOCKEXPR","JOF_UINT16"),
    (211,"GETTHISPROP","JOF_ATOM"),
    (212,"GETARGPROP","JOF_SLOTATOM"),(213,"GETLOCALPROP","JOF_SLOTATOM"),
    (214,"INDEXBASE1","JOF_BYTE"),(215,"INDEXBASE2","JOF_BYTE"),(216,"INDEXBASE3","JOF_BYTE"),
    (217,"CALLGNAME","JOF_ATOM"),(218,"CALLLOCAL","JOF_LOCAL"),(219,"CALLARG","JOF_QARG"),
    (220,"BINDGNAME","JOF_ATOM"),(221,"INT8","JOF_INT8"),(222,"INT32","JOF_INT32"),
    (223,"LENGTH","JOF_BYTE"),(224,"HOLE","JOF_BYTE"),
    (225,"DEFFUN_FC","JOF_OBJECT"),(226,"DEFLOCALFUN_FC","JOF_SLOTOBJECT"),
    (227,"LAMBDA_FC","JOF_OBJECT"),(228,"OBJTOP","JOF_UINT16"),
    (229,"TRACE","JOF_UINT16"),(230,"GETUPVAR_DBG","JOF_UINT16"),
    (231,"CALLUPVAR_DBG","JOF_UINT16"),
    (232,"DEFFUN_DBGFC","JOF_OBJECT"),(233,"DEFLOCALFUN_DBGFC","JOF_SLOTOBJECT"),
    (234,"LAMBDA_DBGFC","JOF_OBJECT"),
    (235,"SETMETHOD","JOF_ATOM"),(236,"INITMETHOD","JOF_ATOM"),
    (237,"UNBRAND","JOF_BYTE"),(238,"UNBRANDTHIS","JOF_BYTE"),
    (239,"SHARPINIT","JOF_UINT16"),
    (240,"GETGLOBAL","JOF_GLOBAL"),(241,"CALLGLOBAL","JOF_GLOBAL"),
    (242,"FUNCALL","JOF_UINT16"),(243,"FORGNAME","JOF_ATOM"),
    # Cocos2d-x custom opcodes (JSB extensions / unused SM 1.8.5 slots)
    # All are JOF_BYTE based on analysis of 119 files — next byte is always a valid opcode
    (244,"JSB_244","JOF_BYTE"),(245,"JSB_245","JOF_BYTE"),
    (246,"JSB_246","JOF_BYTE"),(247,"JSB_247","JOF_BYTE"),
    (248,"JSB_248","JOF_BYTE"),(249,"JSB_249","JOF_BYTE"),
    (250,"JSB_250","JOF_BYTE"),(251,"JSB_251","JOF_BYTE"),
    (252,"JSB_252","JOF_BYTE"),(253,"JSB_253","JOF_BYTE"),
    (254,"JSB_254","JOF_BYTE"),(255,"JSB_255","JOF_BYTE"),
]

OPCODES = {}
for opcode, name, fmt in OPCODE_ENTRIES:
    OPCODES[opcode] = (name, fmt)
JOF_ATOM_SET = set(v[0] for v in OPCODE_ENTRIES if v[2] == 'JOF_ATOM')
JUMP_SET = set(v[0] for v in OPCODE_ENTRIES if v[2] in ('JOF_JUMP', 'JOF_JUMPX'))
STOP_OPS = {197}

BINOP_SYM = {
    15:'|', 16:'^', 17:'&', 18:'===', 19:'!==',
    20:'<', 21:'<=', 22:'>', 23:'>=', 24:'<<', 25:'>>', 26:'>>>',
    27:'+', 28:'-', 29:'*', 30:'/', 31:'%',
    72:'===', 73:'!==', 113:'in', 114:'instanceof',
}
UNOP_SYM = {32:'!', 33:'~', 34:'-', 35:'+', 39:'typeof', 40:'void'}


def get_fl(fmt):
    return SM_FL.get(fmt, 1)


def _is_clean_atom(s):
    """Heuristic: does this string look like a real atom (identifier/literal)?
    Accept printable ASCII, common punctuation, and reasonable Unicode runs.
    Reject obvious garbage (control chars, mostly non-printable)."""
    if not s:
        return True
    # Allow up to a couple of control chars (sentinel \x00) but not lots
    printable = sum(1 for c in s if 0x20 <= ord(c) < 0x7f)
    if printable >= len(s) * 0.8:
        return True
    # Or mostly CJK chars (atoms like "桃园结义")
    cjk = sum(1 for c in s if 0x4e00 <= ord(c) <= 0x9fff)
    if cjk >= len(s) * 0.8:
        return True
    return False


def read_utf16_atoms(xdr, atom_off, natoms, strict=False):
    """Read length-prefixed UTF-16LE atom strings. Returns (atoms, next_offset).

    If strict=True, reject the entire run if the FIRST atom looks like garbage.
    Used by the scan-forward loop to find the correct atom table position.
    """
    atoms = []
    i = atom_off - 4
    while i + 4 < len(xdr) and len(atoms) < natoms:
        nlen = struct.unpack_from('<I', xdr, i)[0]
        if nlen == 0:
            i += 4; continue
        if nlen > 5000:
            break
        i += 4
        if i + nlen * 2 > len(xdr):
            break
        s = xdr[i:i+nlen*2].decode('utf-16-le', errors='replace')
        # Strict mode: bail if first atom is garbage
        if strict and len(atoms) == 0 and not _is_clean_atom(s):
            return [], atom_off
        atoms.append(s)
        i += nlen*2
    # Skip 0xFFFFFFFF / 0x00000000 sentinel
    while i + 4 <= len(xdr):
        v = struct.unpack_from('<I', xdr, i)[0]
        if v in (0xFFFFFFFF, 0):
            i += 4
        else:
            break
    return atoms, i


HEADER_SIZE = 8 + 44  # 4 uint16 prefix + 11 uint32 JSScript header


def _parse_header(xdr, off):
    """Parse a 52-byte object header. Returns dict or None if invalid bounds.
    Uses a relaxed validity check; caller applies stricter atom_idx / size checks.
    """
    if off + HEADER_SIZE > len(xdr):
        return None
    flags, nargs, atom_idx, pad = struct.unpack_from('<4H', xdr, off)
    hdr = struct.unpack_from('<11I', xdr, off + 8)
    length, prologLength, version_packed, natoms_n, nsrcnotes = hdr[:5]
    ntrynotes, nobjects_n, nregexps, nconsts, closedCount, scriptBits = hdr[5:]
    ver = version_packed & 0xFFFF
    nfixed = version_packed >> 16
    if not (length < 50000 and ver == 0xb9 and nfixed < 100 and natoms_n < 5000):
        return None
    return {
        'off': off,
        'flags': flags, 'nargs': nargs, 'atom_idx': atom_idx, 'pad': pad,
        'length': length, 'prolog': prologLength,
        'nfixed': nfixed, 'natoms_n': natoms_n, 'nsrcnotes': nsrcnotes,
        'ntrynotes': ntrynotes, 'nobjects_n': nobjects_n,
        'nregexps': nregexps, 'nconsts': nconsts,
        'closedCount': closedCount, 'scriptBits': scriptBits,
    }


def scan_object_headers(xdr, start, end, parent_atoms):
    """Scan [start, end) byte-by-byte for all valid object headers.
    Returns a list of header dicts (sorted by offset).
    """
    headers = []
    cur = start
    pa_len = max(len(parent_atoms), 256)
    while cur + HEADER_SIZE + 4 <= end:
        h = _parse_header(xdr, cur)
        if h is not None and h['atom_idx'] < pa_len:
            headers.append(h)
        cur += 1
    return headers


def _find_atom_block(xdr, lo, hi, natoms_n):
    """Find a contiguous run of natoms_n UTF-16 length-prefixed strings within
    xdr[lo:hi]. Returns (atoms, atom_start, atom_end) on success, or
    ([], lo, lo) on failure.

    Tries every byte position (some Cocos2d-x objects have atom tables at odd
    offsets because preceding bytecodes/srcnotes/closedvars produce odd byte
    lengths). Prefers exact-count matches; falls back to longest partial run.
    """
    best = ([], lo, lo)
    best_score = -1
    pos = lo
    while pos + 4 <= hi:
        try:
            atoms, after = read_utf16_atoms(xdr, pos, natoms_n, strict=True)
        except Exception:
            atoms, after = [], pos
        # exact match preferred
        if len(atoms) == natoms_n:
            score = sum(len(a) for a in atoms) + 1000
            if score > best_score:
                best = (atoms, pos, after)
                best_score = score
        elif natoms_n > 0 and len(atoms) >= max(2, natoms_n // 2) and best_score < 0:
            score = sum(len(a) for a in atoms)
            if score > best_score:
                best = (atoms, pos, after)
                best_score = score
        pos += 1
    return best


def parse_object_table_scan(xdr, off, parent_atoms, max_count, depth=0):
    """Scan-first parse_object_table:
    1. Enumerate ALL valid headers in [off, end)
    2. Greedy pick the first max_count non-overlapping headers
    3. For each header, locate atom block within [header.next_min, next_header.off)
    4. Recurse for sub-objects within the available region (best effort)
    Returns (results, end_offset).
    """
    if max_count is None or max_count <= 0:
        return [], off

    all_headers = scan_object_headers(xdr, off, len(xdr), parent_atoms)
    if not all_headers:
        return [], off

    # Greedy non-overlapping selection: each picked header must be at least
    # HEADER_SIZE bytes past the previous one (their own data needs that much).
    picked = []
    last_end = off
    for h in all_headers:
        if h['off'] < last_end:
            continue
        picked.append(h)
        last_end = h['off'] + HEADER_SIZE
        if len(picked) >= max_count:
            break

    if len(picked) < max_count:
        return [], off  # signal failure → caller falls back to legacy parser

    results = []
    for i, h in enumerate(picked):
        nxt_off = picked[i+1]['off'] if i + 1 < len(picked) else len(xdr)
        bc_start = h['off'] + HEADER_SIZE
        length = h['length']
        natoms_n = h['natoms_n']

        # Locate atom block within this object's region FIRST — the atom block
        # marks the end of the bytecodes+metadata region.
        atoms_lo = bc_start
        atoms_hi = nxt_off
        if natoms_n > 0:
            nested_atoms, a_start, a_end = _find_atom_block(xdr, atoms_lo, atoms_hi, natoms_n)
        else:
            nested_atoms, a_start, a_end = [], atoms_hi, atoms_hi

        # Bytecodes region: [bc_start, atoms_start). Cocos2d-x stores
        # metadata + true bytecodes before the atom table, and the SM-style
        # `length` field does not exclude this metadata. We hand v9 the full
        # pre-atom region so its prologue scanner can locate the real entry.
        bc_end = a_start if a_start > bc_start else min(bc_start + length, nxt_off)
        bc = xdr[bc_start:bc_end]

        func_name = parent_atoms[h['atom_idx']] if h['atom_idx'] < len(parent_atoms) else f"func_{h['atom_idx']}"

        # Sub-objects: recurse within remaining region [a_end, nxt_off)
        sub_scripts = []
        if h['nobjects_n'] > 0 and a_end < nxt_off:
            try:
                sub_scripts, _ = parse_object_table_scan(
                    xdr[:nxt_off], a_end,
                    nested_atoms if nested_atoms else parent_atoms,
                    h['nobjects_n'], depth + 1)
            except Exception:
                sub_scripts = []

        results.append({
            'name': func_name,
            'nargs': h['nargs'],
            'flags': h['flags'],
            'bc': bc,
            'prolog': h['prolog'],
            'natoms': natoms_n,
            'nested_atoms': nested_atoms,
            'nobjects': h['nobjects_n'],
            'sub_scripts': sub_scripts,
            'raw_end': nxt_off,
            'header_off': h['off'],
            'atoms_off': a_start,
            'atoms_end': a_end,
        })

    return results, picked[-1]['off'] + HEADER_SIZE


def parse_object_table(xdr, off, parent_atoms, depth=0, max_count=None):
    """Parse nested script objects from remaining data after atoms.
    Each entry header: flags(2) nargs(2) atom(2) pad(2) + 44-byte SM script header.
    Then bytecodes + srcnotes + atoms + sub-objects.
    Returns list of object dicts.

    Strategy: try the scan-first parser when max_count is known. If it yields
    `max_count` results, use them. Otherwise fall back to the legacy stride-based
    parser (kept verbatim below to avoid regressing already-working files).
    """
    if max_count is not None and max_count > 0:
        try:
            scan_results, scan_end = parse_object_table_scan(
                xdr, off, parent_atoms, max_count, depth)
            if len(scan_results) == max_count:
                return scan_results, scan_end
        except Exception:
            pass
    return _parse_object_table_legacy(xdr, off, parent_atoms, depth, max_count)


def _parse_object_table_legacy(xdr, off, parent_atoms, depth=0, max_count=None):
    results = []
    count = 0
    HEADER_SIZE = 8 + 44  # 4 uint16 prefix + 11 uint32 JSScript header

    while off + HEADER_SIZE + 4 <= len(xdr):
        if max_count is not None and count >= max_count:
            break

        flags, nargs, atom_idx, pad = struct.unpack_from('<4H', xdr, off)
        hdr = struct.unpack_from('<11I', xdr, off + 8)
        length, prologLength, version_packed, natoms_n, nsrcnotes = hdr[:5]
        ntrynotes, nobjects, nregexps, nconsts, closedCount, scriptBits = hdr[5:]
        ver = version_packed & 0xFFFF
        nfixed = version_packed >> 16

        # Allow length=0 (empty function body); only reject obvious garbage
        if not (length < 50000 and ver == 0xb9 and nfixed < 100 and natoms_n < 5000):
            off += 1
            continue

        func_name = parent_atoms[atom_idx] if atom_idx < len(parent_atoms) else f'func_{atom_idx}'

        bc_start = off + HEADER_SIZE
        data_end = bc_start + length  # total data section end

        # Cocos2d-x nested function format: atoms FIRST in the data section,
        # followed by bytecodes, source notes, consts, etc.
        # Try to detect and handle this format.
        nested_atoms = []
        after_atoms = data_end  # default: no sub-object data
        bc = xdr[bc_start:data_end]  # default: raw data as bytecodes

        # Try reading atoms from START of data section (Cocos2d-x format)
        test_atoms, test_end = read_utf16_atoms(xdr, bc_start + 4, max(natoms_n, 100), strict=False)
        if test_atoms and len(test_atoms) >= 2:
            atom_bytes = test_end - bc_start
            # Sanity: atom table must not consume >80% of data section,
            # otherwise it's likely bytecodes being misread as atoms.
            if 8 < atom_bytes < min(length, 16384) and test_end < bc_start + length * 0.8:
                # Likely Cocos2d-x format: atoms at start
                nested_atoms = test_atoms
                # After atoms: [bytecodes+consts] then [closed vars] [trynotes] [srcnotes]
                # Exclude closed vars + trynotes + srcnotes from bc_len.
                closed_start = data_end - nsrcnotes - ntrynotes * 12 - closedCount * 2
                bc_len = closed_start - test_end
                if bc_len > 0:
                    bc_raw = xdr[test_end:closed_start]
                    # Scan past prologue (NOP/ENTERWITH/POPV) + const data to find
                    # the real bytecode start. Look for longest valid opcode run.
                    best_off = 0
                    best_run = 0
                    max_scan = min(len(bc_raw), 500)
                    for scan in range(max_scan):
                        pc = scan
                        run = 0
                        while pc < len(bc_raw):
                            op = bc_raw[pc]
                            if op in OPCODES:
                                name, fmt = OPCODES[op]
                                sz = SM_FL.get(fmt, 1)
                                if sz <= 0: sz = 1
                                if pc + sz > len(bc_raw): break
                                if fmt == 'JOF_ATOM':
                                    idx = bc_raw[pc + 4]
                                    if idx >= len(nested_atoms): break
                                run += 1
                                pc += sz
                            else:
                                break
                        if run > best_run:
                            best_run = run
                            best_off = scan
                        if run > 20:
                            break
                    if best_run > 5:
                        bc = xdr[test_end + best_off:closed_start]
                    else:
                        bc = bc_raw
                    # after_atoms = rough position after this function's data
                    after_atoms = data_end
                else:
                    bc = b''
                    after_atoms = test_end

        if not nested_atoms:
            # Fallback to standard SM format: bytecodes first, then sn, trynotes, atoms
            sn_start = bc_start + length
            sn_end = sn_start + nsrcnotes
            TRYNOTE_SIZE = 12
            trynotes_end = sn_end + ntrynotes * TRYNOTE_SIZE

            after_atoms = trynotes_end
            if natoms_n > 0:
                for scan_delta in range(0, 4096, 2):
                    scan_pos = trynotes_end + scan_delta
                    if scan_pos + 4 > len(xdr):
                        break
                    try:
                        test_atoms, test_after = read_utf16_atoms(xdr, scan_pos, natoms_n, strict=True)
                        if test_atoms and len(test_atoms) >= max(2, natoms_n // 2):
                            nested_atoms = test_atoms
                            after_atoms = test_after
                            break
                    except Exception:
                        continue
                if not nested_atoms:
                    for scan_delta in range(0, 4096, 2):
                        scan_pos = trynotes_end + scan_delta
                        if scan_pos + 4 > len(xdr):
                            break
                        try:
                            test_atoms, test_after = read_utf16_atoms(xdr, scan_pos, natoms_n)
                            if test_atoms:
                                nested_atoms = test_atoms
                                after_atoms = test_after
                                break
                        except Exception:
                            continue
                if not nested_atoms:
                    after_atoms = trynotes_end

        # Sub-objects (recursive)
        sub_scripts = []
        sub_end = after_atoms
        if nobjects > 0 and after_atoms + HEADER_SIZE <= len(xdr):
            try:
                sub_scripts, sub_end = parse_object_table(
                    xdr, after_atoms,
                    nested_atoms if nested_atoms else parent_atoms,
                    depth + 1, max_count=nobjects)
            except Exception:
                sub_scripts = []
                sub_end = after_atoms

        results.append({
            'name': func_name,
            'nargs': nargs,
            'flags': flags,
            'bc': bc,
            'prolog': prologLength,
            'natoms': natoms_n,
            'nested_atoms': nested_atoms,
            'nobjects': nobjects,
            'sub_scripts': sub_scripts,
            'raw_end': sub_end,
        })
        off = sub_end
        count += 1

    return results, off


def _is_jsb_binding(bc):
    """Check if bytecodes are JSB native binding (inline string data) vs standard SM.

    v8 rewrite: use walk-completeness as the primary signal. The previous v7
    Pattern 3 (`bc[0]==0 && bc[2]==0 && bc[3]==0 && bc[1]!=0`) had a CRITICAL
    false-positive: it flagged any file starting with NOP+GETPROP(atom_idx<256)
    as JSB inline data. Files like Tools/Net.jsc, Cfg/Url.jsc, Profile/UserCfg.jsc
    and Scene/Login/LoginScene_BfSdk.jsc all start with `00 35 00 00 00 01` =
    `NOP GETPROP(atom_1)`, satisfying the broken pattern and being misclassified.

    The new heuristic:
      1. Files starting with 0x40 (NULL opcode) are explicit JSB markers.
      2. Otherwise, walk the bytecode with the SM_FL table. If <60% of bytes
         are consumed by valid opcode parsing, it's data (JSB inline).
      3. Strong alternating-null UTF-16LE pattern is also a signal.
    """
    if not bc or len(bc) < 8:
        return False

    # Pattern 1: starts with 0x40 (NULL opcode) — JSB marker
    if bc[0] == 0x40:
        return True

    # Pattern 4 (kept): strong alternating-null UTF-16LE pattern at start
    check_len = min(len(bc), 200)
    if check_len >= 16:
        null_count = bc[:check_len].count(0)
        null_ratio = null_count / check_len if check_len > 0 else 0
        alt_null_count = 0
        alt_total = 0
        for i in range(1, check_len, 2):
            alt_total += 1
            if bc[i] == 0:
                alt_null_count += 1
        alt_ratio = alt_null_count / alt_total if alt_total > 0 else 0
        # True UTF-16LE: >80% of odd bytes are null AND >30% null overall
        if alt_ratio > 0.80 and null_ratio > 0.30:
            return True

    # Pattern 5: Walk bytecodes — if fewer than 60% of bytes are consumed by valid
    # opcode parsing, it's likely data, not real bytecode.
    off = 0
    consumed = 0
    while off < len(bc):
        b = bc[off]
        if b in OPCODES:
            fl = get_fl(OPCODES[b][1])
            if fl <= 0:  # variable-length, can't validate
                consumed += 1
                off += 1
            else:
                consumed += fl
                off += fl
        else:
            off += 1  # skip unknown byte, count as not consumed
    if len(bc) > 0 and (consumed / len(bc)) < 0.60:
        return True

    return False


def walk_bc(bc):
    """Walk bytecodes to verify parsing. Returns final offset."""
    off = 0
    while off < len(bc):
        b = bc[off]
        if b in OPCODES:
            _, fmt = OPCODES[b]
            fl = get_fl(fmt)
            if fl <= 0:  # variable-length
                fl = 1  # conservative: advance by 1
            if off + fl > len(bc):
                break
        else:
            fl = 1
        off += fl
    return off


class JSCReader:
    def __init__(self):
        pass

    def analyze_jsc(self, fname):
        path = os.path.join(JSC_DIR, fname) if not os.path.isabs(fname) else fname
        with open(path, 'rb') as f:
            data = f.read()
        fields = [struct.unpack_from('<I', data, 4 + i*4)[0] for i in range(13)]
        natoms = fields[4]
        field1 = fields[1]   # bytecode length
        field5 = fields[5]   # source notes length
        nobjects = fields[7]  # object table count

        path_end = data.index(b'\x00', 60)
        xdr_start = path_end + 1
        while xdr_start < len(data) and data[xdr_start] == 0:
            xdr_start += 1
        xdr = data[xdr_start:]

        # Root bytecodes
        bc = xdr[16:16+field1]

        # Root atoms.
        # In SM 1.8.5 XDR, objects/regexps/consts are serialized BEFORE atoms.
        # Scan forward from expected offset to find real atom table.
        # Start from: 16 + bc_len + srcnotes_len (minimum possible atom offset)
        atom_off = 16 + field1 + field5
        atoms, obj_off = read_utf16_atoms(xdr, atom_off, natoms)

        # If not found at minimum position, scan forward up to 8192 bytes.
        # The gap contains trynotes, objects, regexps, consts, and closed vars.
        if not atoms and natoms > 0:
            for scan_delta in range(0, 8192, 2):
                scan_pos = atom_off + scan_delta
                if scan_pos + 4 > len(xdr):
                    break
                try:
                    test_atoms, test_after = read_utf16_atoms(xdr, scan_pos, natoms)
                    if test_atoms:
                        # Verify: atoms should be at least partially valid
                        # (not binary garbage from nested objects)
                        if len(test_atoms) >= min(3, natoms):
                            atoms = test_atoms
                            obj_off = test_after
                            break
                except Exception:
                    continue

        # Object table (nested scripts). Pass nobjects as max_count so the
        # scan-first parser can greedily pick exactly that many headers.
        remaining = xdr[obj_off:]
        if nobjects > 0 and len(remaining) > 60:
            objects, _ = parse_object_table(remaining, 0, atoms, 0, max_count=nobjects)
        else:
            objects = []

        return bc, atoms, field1, field5, natoms, nobjects, objects, xdr

    @staticmethod
    def _parse_switch_len(bc, off, name):
        """Parse variable-length switch bytecodes to determine instruction size.
        TABLESWITCH: 1 + 4(low) + 4(high) + N*4(offsets) + 4(default)
        TABLESWITCHX: 1 + 4(low) + 4(high) + N*4(offsets)  (no default)
        LOOKUPSWITCH: 1 + 4(npairs) + N*8(key+offset) + 4(default)
        LOOKUPSWITCHX: 1 + 4(npairs) + N*8(key+offset)  (no default)
        Returns total instruction length in bytes (minimum 1).
        """
        if off + 5 > len(bc):
            return 1
        if 'TABLESWITCH' in name:
            if off + 9 > len(bc):
                return 1
            low = struct.unpack_from('<i', bc, off + 1)[0]
            high = struct.unpack_from('<i', bc, off + 5)[0]
            n = max(0, high - low + 1)
            if n > 10000:  # sanity check
                return 1
            if 'X' in name:
                return 1 + 8 + n * 4  # no default
            else:
                return 1 + 8 + n * 4 + 4  # with default
        elif 'LOOKUPSWITCH' in name:
            npairs = struct.unpack_from('<i', bc, off + 1)[0]
            if npairs < 0 or npairs > 10000:  # sanity check
                return 1
            if 'X' in name:
                return 1 + 4 + npairs * 8  # no default
            else:
                return 1 + 4 + npairs * 8 + 4  # with default
        return 1

    def disasm(self, bc, atoms, nested_objects=None, obj_index=0):
        """
        Disassemble bytecodes using SM 1.8.5 instruction sizes.
        JOF_ATOM: read uint32 operand = atom index.
        JOF_JUMP: read int16 operand = offset from instruction START.
        Returns (instructions, atom_usage_count, stopped)
        """
        instructions = []
        off = 0
        stopped = False
        while off < len(bc):
            b = bc[off]
            if b in STOP_OPS:
                instructions.append((off, b, OPCODES[b][0], None, None, None, None))
                off += 1
                stopped = True
                break
            if b in OPCODES:
                name, fmt = OPCODES[b]
                fl = get_fl(fmt)
                # Handle variable-length switch opcodes
                if fl <= 0:
                    fl = self._parse_switch_len(bc, off, name)
                if off + fl > len(bc):
                    instructions.append((off, b, "TRUNC_" + name, None, None, None, None))
                    off += 1
                    continue

                atom_str = None
                value = None
                raw = None

                if fl == 1:
                    pass  # no operand
                elif fmt == 'JOF_ATOM':
                    # uint32 operand: atom index in HIGH byte (LE >> 24)
                    operand = struct.unpack_from('<I', bc, off+1)[0]
                    atom_idx = operand >> 24
                    raw = "%08x" % atom_idx
                    atom_str = atoms[atom_idx] if atom_idx < len(atoms) else "?atom%d" % atom_idx
                elif fmt == 'JOF_JUMP':
                    # int16 offset from start of instruction
                    offset = struct.unpack_from('<h', bc, off+1)[0]
                    raw = "%04x" % (offset & 0xFFFF)
                    value = off + offset  # SM 1.8.5: target = pc + offset
                elif fmt in ('JOF_OBJECT', 'JOF_REGEXP'):
                    # Cocos2d-x: 5-byte instruction, index in HIGH byte of LE uint32 (byte off+4)
                    operand = struct.unpack_from('<I', bc, off+1)[0]
                    obj_idx = operand >> 24
                    raw = "%08x" % obj_idx
                    value = obj_idx
                elif fmt in ('JOF_UINT16', 'JOF_QARG', 'JOF_LOCAL', 'JOF_GLOBAL'):
                    operand = struct.unpack_from('<H', bc, off+1)[0]
                    raw = "%04x" % operand
                    value = operand
                elif fmt == 'JOF_UINT8':
                    operand = bc[off+1]
                    raw = "%02x" % operand
                    value = operand
                elif fmt == 'JOF_INT8':
                    operand = struct.unpack_from('<b', bc, off+1)[0]
                    raw = "%02x" % (operand & 0xFF)
                    value = operand
                elif fmt == 'JOF_UINT24':
                    operand = (bc[off+1] << 16) | (bc[off+2] << 8) | bc[off+3]
                    raw = "%06x" % operand
                    value = operand
                elif fmt == 'JOF_INT32':
                    operand = struct.unpack_from('<i', bc, off+1)[0]
                    raw = "%08x" % (operand & 0xFFFFFFFF)
                    value = operand
                elif fmt == 'JOF_JUMPX':
                    offset = struct.unpack_from('<i', bc, off+1)[0]
                    raw = "%08x" % (offset & 0xFFFFFFFF)
                    value = off + offset
                elif fmt == 'JOF_SLOTATOM':
                    slot = struct.unpack_from('<H', bc, off+1)[0]
                    atom_idx = struct.unpack_from('<H', bc, off+3)[0]
                    raw = "slot:%d atom:%d" % (slot, atom_idx)
                    atom_str = atoms[atom_idx] if atom_idx < len(atoms) else "?atom%d" % atom_idx
                    value = slot
                elif fmt in ('JOF_UINT16PAIR', 'JOF_SLOTOBJECT'):
                    raw = ' '.join('%02x' % bc[off+i] for i in range(1, fl))
                else:
                    raw = ' '.join('%02x' % bc[off+i] for i in range(1, fl))

                instructions.append((off, b, name, fmt, raw, value, atom_str))
                off += fl
            else:
                instructions.append((off, b, "UNKNOWN_0x%02x" % b, None, None, None, None))
                off += 1
        return instructions, stopped


class JSCDecompiler:
    """Linear pattern-matching decompiler with recursive function body support."""

    def __init__(self, instructions, atoms, nested_objects=None, fname="",
                 parent_atoms=None):
        self.insns = instructions
        self.atoms = atoms
        self.nested_objects = nested_objects or []
        self.fname = fname
        self.parent_atoms = parent_atoms or atoms
        self._obj_index = 0
        self.labels = set()
        for off, b, name, fmt, raw, value, atom in self.insns:
            if b in JUMP_SET and isinstance(value, int):
                fl = get_fl(fmt) if fmt else 3
                next_off = off + fl
                if value not in (next_off, off):  # not jump-to-next, not self
                    self.labels.add(value)
        self.label_map = {}
        self.next_label = 1
        # Structure analysis
        self._struct_info = None

    def _label_name(self, off):
        if off not in self.label_map:
            self.label_map[off] = "L%d" % self.next_label
            self.next_label += 1
        return self.label_map[off]

    def _is_debug_marker(self, s):
        if not s: return False
        markers = ['public ', 'main ', '.js begin', '.js end']
        return any(m in s for m in markers)

    def _is_version_string(self, s):
        if not s: return False
        parts = s.split('.')
        if len(parts) < 2: return False
        return all(p.isdigit() for p in parts)

    def _pop(self, stack):
        return stack.pop() if stack else 'undefined'

    def _peek(self, stack):
        return stack[-1] if stack else 'undefined'

    def _is_cc_log_prologue(self, insns):
        if not insns: return None
        idx = 0
        while idx < len(insns) and insns[idx][1] == 0: idx += 1  # skip NOP
        if idx >= len(insns) or insns[idx][1] != 12: return None  # DUP
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 184: return None  # XMLCOMMENT "cc"
        if insns[idx][-1] != 'cc': return None
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 1: return None  # PUSH
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 10: return None  # FORARG
        if insns[idx][4] != 'e4': return None  # raw operand hex "e4"
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 61: return None  # STRING
        if insns[idx][-1] != 'log': return None
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 2: return None  # POPV
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx < len(insns) and insns[idx][1] == 228:  # OBJTOP
            idx += 1
            while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 1: return None  # PUSH
        idx += 1
        while idx < len(insns) and insns[idx][1] == 0: idx += 1
        if idx >= len(insns) or insns[idx][1] != 2: return None  # POPV
        idx += 1
        return idx

    def _analyze_structure(self, insns):
        """Analyze instruction list for structured control flow patterns.
        Returns dict: offset -> (action, extra_info)
        Actions: 'if_start', 'else_label', 'end_label', 'goto_mid',
                 'loop_back', 'while_cont', 'label'
        Handles out-of-range jump targets by approximating scope end.
        """
        off_to_idx = {insn[0]: i for i, insn in enumerate(insns)}
        last_off = insns[-1][0] if insns else 0
        struct = {}

        for i, insn in enumerate(insns):
            off, b, name, fmt, raw, value, atom = insn
            fl = get_fl(fmt) if fmt else 3
            next_off = off + fl

            if b == 7 and isinstance(value, int):  # IFEQ
                if value == next_off or value == off:
                    continue
                target_in_range = value in off_to_idx
                if not target_in_range and value >= last_off + 10:
                    # Out of range — body extends until next IFEQ/IFNE/GOTO
                    # or end of instruction list
                    body_end = len(insns)
                    for j in range(i + 1, len(insns)):
                        jb = insns[j][1]
                        if jb in (6, 7, 8):  # GOTO, IFEQ, IFNE
                            body_end = j
                            break
                    # Mark as if_start with sentinel target
                    struct[off] = ('if_start_out', body_end, None)
                    continue

                target_idx = off_to_idx.get(value)
                if target_idx is None:
                    continue

                # Check for if-else pattern: IFEQ Lelse; ... GOTO Lend; Lelse: ... Lend:
                has_else = False
                if target_idx > i + 1 and target_idx < len(insns):
                    prev = insns[target_idx - 1]
                    if prev[1] == 6 and isinstance(prev[5], int):  # GOTO before target
                        goto_target = prev[5]
                        if goto_target in off_to_idx and off_to_idx[goto_target] > target_idx:
                            has_else = True
                            struct[off] = ('if_start', value, prev[5])
                            struct[prev[0]] = ('goto_mid',)
                            if value not in struct:
                                struct.setdefault(value, ('else_label',))
                            if prev[5] not in struct:
                                struct.setdefault(prev[5], ('end_label',))
                if not has_else:
                    struct[off] = ('if_start', value, None)
                    if value not in struct:
                        struct.setdefault(value, ('end_label',))

            elif b == 8 and isinstance(value, int):  # IFNE
                if value == next_off or value == off or value not in off_to_idx:
                    continue
                if off_to_idx[value] < i:
                    # Backward edge → potential loop continue
                    struct[off] = ('while_cont', value)

            elif b == 6 and isinstance(value, int):  # GOTO
                if value == next_off or value == off:
                    continue
                if value in off_to_idx and off_to_idx[value] < i:
                    # Backward edge → loop bottom
                    struct[off] = ('loop_back', value)

        # Mark remaining labels — include out-of-range ones as plain labels
        for off in sorted(self.labels):
            if off not in struct:
                struct[off] = ('label',)

        return struct

    def decompile(self):
        self._build_labels(self.insns)
        lines = []
        self._decompile_insns(self.insns, lines, 0, skip_prologue=True)
        js = '\n'.join(lines)
        js = self._restructure_text(js)
        return js

    def _build_labels(self, insns):
        """Build label set from jump instructions."""
        self.labels = set()
        for off, b, name, fmt, raw, value, atom in insns:
            if b in JUMP_SET and isinstance(value, int):
                fl = get_fl(fmt) if fmt else 3
                next_off = off + fl
                if value not in (next_off, off):
                    self.labels.add(value)
        self.label_map = {}
        self.next_label = 1

    def _restructure_text(self, text):
        """Post-process decompiled text to replace goto/label patterns with structured blocks.
        Pattern 1: 'if (!(cond)) goto Lx;\nbody\nLx:' -> 'if (cond) {\nbody\n}'
        Pattern 2: 'if (!(cond)) goto Lx;\nbody\ngoto Ly;\nLx:\nelse_body\nLy:' -> 'if (cond) {\nbody\n} else {\nelse_body\n}'
        Pattern 3: 'Lx:' (dead/unused labels) -> remove
        """
        lines = text.split('\n')
        # Process: find if-goto patterns and replace with structured blocks
        # Strategy: scan for labels and their usages
        label_usage = {}  # label_name -> {used_by: [], defined_at: None}
        label_defs = {}   # label_name -> line_index

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.endswith(':') and len(stripped) > 1 and stripped[0].isalpha():
                name = stripped[:-1]
                label_defs[name] = i
                if name not in label_usage:
                    label_usage[name] = {'used_by': [], 'defined_at': i}
                else:
                    label_usage[name]['defined_at'] = i

            # Check for goto
            if stripped.startswith('goto ') and stripped.endswith(';'):
                name = stripped[5:-1]
                if name not in label_usage:
                    label_usage[name] = {'used_by': [], 'defined_at': None}
                label_usage[name]['used_by'].append(i)

            # Check for if-goto: "if (!(cond)) goto Lx;" or "if (cond) goto Lx;"
            if stripped.startswith('if (!(') and stripped.endswith(';'):
                # Find goto inside
                goto_part = stripped[stripped.rfind('goto '):]
                if goto_part.startswith('goto '):
                    name = goto_part[5:-1]
                    if name not in label_usage:
                        label_usage[name] = {'used_by': [], 'defined_at': None}
                    label_usage[name]['used_by'].append(i)

            if stripped.startswith('if (') and 'goto ' in stripped and stripped.endswith(';'):
                goto_part = stripped[stripped.rfind('goto '):]
                if goto_part.startswith('goto '):
                    name = goto_part[5:-1]
                    if name not in label_usage:
                        label_usage[name] = {'used_by': [], 'defined_at': None}
                    label_usage[name]['used_by'].append(i)

        # Find labels that are only used once by an if-goto and can be restructured
        restructured = set()  # line indices of lines to remove
        replacements = {}     # line index -> replacement text

        for name, info in label_usage.items():
            if name not in label_defs:
                continue
            def_idx = label_defs[name]
            used_indices = info['used_by']

            if len(used_indices) == 1:
                use_idx = used_indices[0]
                goto_line = lines[use_idx].strip()

                # Pattern: if (!(cond)) goto Lx; at use_idx, body, Lx: at def_idx
                if goto_line.startswith('if (!(') and goto_line.endswith(');'):
                    # Extract condition (negated)
                    cond = goto_line[6:-9]  # remove 'if (!(' from start and ') goto Lx;' from end
                    # The ';' is at the end, and 'goto Lx)' ends with ')'
                    # "if (!(condition)) goto Lx;"
                    # split on ') goto '
                    parts = goto_line[6:-1].split(') goto ')
                    if len(parts) == 2:
                        neg_cond = parts[0]
                        label_name = parts[1][:-1]  # remove ';'

                        # Body = lines between use_idx and def_idx
                        body_lines = []
                        for j in range(use_idx + 1, def_idx):
                            if lines[j].strip():
                                body_lines.append(lines[j])

                        # Check if there's a goto before def_idx (if-else pattern)
                        else_goto_idx = None
                        for j in range(use_idx + 1, def_idx):
                            if lines[j].strip().startswith('goto ') and lines[j].strip().endswith(';'):
                                else_goto_idx = j
                                break

                        # Check for else body
                        has_else = False
                        else_body_lines = []
                        if else_goto_idx is not None:
                            goto_name = lines[else_goto_idx].strip()[5:-1]
                            # Check if the goto target is after def_idx
                            if goto_name in label_defs and label_defs[goto_name] > def_idx:
                                end_idx = label_defs[goto_name]
                                # Body before the goto
                                body_lines = []
                                for j in range(use_idx + 1, else_goto_idx):
                                    if lines[j].strip():
                                        body_lines.append(lines[j])
                                # Else body: between def_idx and end_idx
                                for j in range(def_idx + 1, end_idx):
                                    if lines[j].strip():
                                        else_body_lines.append(lines[j])
                                has_else = True
                                # Mark goto and end label for removal
                                restructured.add(else_goto_idx)
                                restructured.add(end_idx)
                        if not has_else:
                            # Remove trailing blank lines before label
                            while body_lines and body_lines[-1].startswith('// goto') or body_lines and body_lines[-1].startswith('L'):
                                body_lines = body_lines[:-1]

                        # Build replacement
                        indent = ''
                        if use_idx < len(lines):
                            ind = lines[use_idx][:len(lines[use_idx]) - len(lines[use_idx].lstrip())]
                            indent = ind

                        new_lines = []
                        new_lines.append(indent + "if (%s) {" % neg_cond)
                        for bl in body_lines:
                            bl_stripped = bl.lstrip()
                            if bl_stripped.startswith('L') and bl_stripped.endswith(':'):
                                continue  # skip labels in body
                            new_lines.append(indent + '    ' + bl_stripped if not bl.startswith(' ') else bl)
                        if has_else:
                            new_lines.append(indent + "} else {")
                            for bl in else_body_lines:
                                bl_stripped = bl.lstrip()
                                if bl_stripped.startswith('L') and bl_stripped.endswith(':'):
                                    continue
                                new_lines.append(indent + '    ' + bl_stripped if not bl.startswith(' ') else bl)
                        new_lines.append(indent + "}")

                        # Replace the if-goto line with structured form
                        # And remove body + label lines
                        replacements[use_idx] = new_lines
                        for j in range(use_idx + 1, def_idx + 1):
                            restructured.add(j)
                        if has_else:
                            restructured.add(else_goto_idx)
                            restructured.add(label_defs.get(goto_name, -1))

        # Apply restructuring
        new_lines = []
        for i, line in enumerate(lines):
            if i in restructured:
                continue
            if i in replacements:
                new_lines.extend(replacements[i])
            else:
                new_lines.append(line)

        # Clean up: remove orphaned label-only lines, repeated blank lines
        result = []
        prev_blank = False
        for line in new_lines:
            stripped = line.strip()
            # Skip label-only lines that are no longer referenced
            if stripped.endswith(':') and len(stripped) > 1 and stripped[0].isalpha():
                name = stripped[:-1]
                if name in label_usage:
                    # Keep label if it still has any non-restructured goto references
                    has_live_refs = any(u not in restructured for u in label_usage[name]['used_by'])
                    if not has_live_refs:
                        continue
                else:
                    continue  # orphaned label
            if stripped == '' or stripped.startswith('//'):
                if not prev_blank:
                    result.append(line)
                    prev_blank = stripped == ''
            else:
                result.append(line)
                prev_blank = False

        return '\n'.join(result)

    def _find_insn_idx(self, insns, target_off):
        """Find instruction index by offset."""
        for j in range(len(insns)):
            if insns[j][0] == target_off:
                return j
        return None

    def _decompile_structured(self, insns, lines, indent, skip_prologue=False,
                              struct_info=None, in_with=False):
        """Decompile with structured control flow using structure info."""
        if struct_info is None:
            struct_info = self._struct_info if insns is self.insns else {}
        stack = ['this']
        init_stack = []
        i = 0
        with_depth = 0

        if skip_prologue:
            prologue_end = self._is_cc_log_prologue(insns)
            if prologue_end is not None:
                stack.append('this')
                stack.append('"cc"')
                stack.append('undefined')
                i = prologue_end

        while i < len(insns):
            off, b, name, fmt, raw, value, atom = insns[i]
            base = name.split('[')[0] if '[' in name else name
            fl_insn = get_fl(fmt) if fmt else 3
            next_off = off + fl_insn

            action = struct_info.get(off)

            # --- Structured if/if-else ---
            if action and action[0] == 'if_start':
                target = action[1]
                end_target = action[2]
                target_idx = self._find_insn_idx(insns, target)
                if target_idx is None or target_idx <= i:
                    # Fallback: emit goto
                    cond = self._pop(stack)
                    lines.append(self._ind(indent) + "if (!(%s)) goto %s;" % (cond, self._label_name(target)))
                    i += 1
                    continue

                cond = self._pop(stack)
                lines.append(self._ind(indent) + "if (%s) {" % cond)

                # Then-body
                if end_target is not None:
                    # if-else: find where the end label is
                    end_idx = self._find_insn_idx(insns, end_target)
                    then_end = target_idx if end_idx is None else end_idx
                else:
                    then_end = target_idx

                then_insns = insns[i + 1:then_end]
                if end_target is not None and then_insns and then_insns[-1][1] == 6:
                    then_insns = then_insns[:-1]  # remove trailing GOTO

                if then_insns:
                    self._decompile_structured(then_insns, lines, indent + 1,
                                               struct_info=struct_info)

                if end_target is not None:
                    lines.append(self._ind(indent) + "} else {")
                    else_end = self._find_insn_idx(insns, end_target)
                    if else_end is not None:
                        else_insns = insns[target_idx:else_end]
                        if else_insns:
                            self._decompile_structured(else_insns, lines, indent + 1,
                                                       struct_info=struct_info)

                lines.append(self._ind(indent) + "}")

                # Advance to end
                if end_target is not None:
                    ni = self._find_insn_idx(insns, end_target)
                    i = ni if ni is not None else target_idx
                else:
                    i = target_idx
                continue

            # --- Structured if with out-of-range target ---
            if action and action[0] == 'if_start_out':
                body_end = action[1]  # index of next IFEQ/GOTO or end
                cond = self._pop(stack)
                lines.append(self._ind(indent) + "if (%s) {" % cond)
                body_insns = insns[i + 1:body_end]
                if body_insns:
                    self._decompile_structured(body_insns, lines, indent + 1,
                                               struct_info=struct_info)
                lines.append(self._ind(indent) + "}")
                i = body_end
                continue

            # --- Structured loops (placeholder - emits goto for now) ---
            if action and action[0] == 'loop_back':
                lines.append(self._ind(indent) + "// loop back (goto 0x%x)" % action[1])
                i += 1
                continue

            # --- Skip labels handled by if/if-else ---
            if action and action[0] in ('else_label', 'end_label'):
                i += 1
                continue

            # --- Skip GOTO in middle of if-else ---
            if action and action[0] == 'goto_mid':
                i += 1
                continue

            # --- Regular label ---
            if action and action[0] == 'label':
                lines.append("")
                lines.append("%s:" % self._label_name(off))
                i += 1
                continue

            # === Normal instruction processing ===
            result = self._exec_insn(off, b, name, base, fmt, raw, value, atom,
                                     stack, lines, indent, insns, i,
                                     in_with=(in_with or with_depth > 0),
                                     init_stack=init_stack)

            if result == 'stop':
                break
            elif result == 'skip_with_block':
                with_depth += 1
                depth = 1
                j = i + 1
                while j < len(insns):
                    joff, jb, jname, jfmt, jraw, jval, jatm = insns[j]
                    jbase = jname.split('[')[0] if '[' in jname else jname
                    if jbase == 'LEAVEWITH':
                        depth -= 1
                        if depth == 0: break
                    elif jbase == 'ENTERWITH':
                        depth += 1
                    j += 1
                body = insns[i+1:j]
                if body:
                    body_lines = []
                    self._decompile_structured(body, body_lines, indent + 1,
                                               struct_info=struct_info,
                                               in_with=(in_with or with_depth > 0))
                    for l in body_lines:
                        lines.append(l)
                lines.append(self._ind(indent) + "}")
                i = j
                if i < len(insns):
                    i += 1
                continue
            elif result == 'skip_to_label':
                i += 1
                while i < len(insns):
                    next_off = insns[i][0]
                    if next_off in self.labels:
                        stack[:] = ['this']
                        with_depth = 0
                        break
                    i += 1
                continue

            i += 1

        return '\n'.join(lines)

    def _decompile_insns(self, insns, lines, indent, in_with=False, skip_prologue=False):
        """Linear decompilation of instructions — stack-based, no CFG restructuring."""
        stack = ['this']
        init_stack = []
        i = 0
        with_depth = 0
        pending_out_ifs = 0  # out-of-range IFEQ blocks awaiting closing '}'
        emitted_labels = set()  # track which labels got emitted inline

        if skip_prologue:
            prologue_end = self._is_cc_log_prologue(insns)
            if prologue_end is not None:
                stack.append('this')
                stack.append('"cc"')
                stack.append('undefined')
                i = prologue_end

        while i < len(insns):
            off, b, name, fmt, raw, value, atom = insns[i]
            base = name.split('[')[0] if '[' in name else name

            # Emit label if this offset is a jump target (only for in-range labels)
            if off in self.labels and insns is self.insns:
                emitted_labels.add(off)
                # Close pending out-of-range if-blocks before label
                while pending_out_ifs > 0:
                    lines.append(self._ind(indent + pending_out_ifs - 1) + "}")
                    pending_out_ifs -= 1
                lines.append("")
                lines.append("%s:" % self._label_name(off))

            result = self._exec_insn(off, b, name, base, fmt, raw, value, atom,
                                     stack, lines, indent, insns, i,
                                     in_with=(in_with or with_depth > 0),
                                     init_stack=init_stack)

            if result == 'stop':
                break
            elif result == 'out_if':
                # Out-of-range IFEQ — 'if (cond) {' was emitted, track nesting
                pending_out_ifs += 1
                i += 1
                continue
            elif result == 'skip_with_block':
                with_depth += 1
                depth = 1
                j = i + 1
                while j < len(insns):
                    joff, jb, jname, jfmt, jraw, jval, jatm = insns[j]
                    jbase = jname.split('[')[0] if '[' in jname else jname
                    if jbase == 'LEAVEWITH':
                        depth -= 1
                        if depth == 0:
                            break
                    elif jbase == 'ENTERWITH':
                        depth += 1
                    j += 1
                body = insns[i+1:j]
                if body:
                    body_lines = []
                    self._decompile_insns(body, body_lines, indent + 1,
                                         in_with=(in_with or with_depth > 0))
                    for line in body_lines:
                        lines.append(line)
                lines.append(self._ind(indent) + "}")
                i = j
                if i < len(insns):
                    i += 1
                continue
            elif result == 'skip_to_label':
                i += 1
                while i < len(insns):
                    next_off = insns[i][0]
                    if next_off in self.labels:
                        stack[:] = ['this']
                        with_depth = 0
                        break
                    i += 1
                continue

            i += 1

        # Close any remaining out-of-range if-blocks
        while pending_out_ifs > 0:
            lines.append(self._ind(indent + pending_out_ifs - 1) + "}")
            pending_out_ifs -= 1

        # Emit labels that are in self.labels but never appeared at an instruction
        # boundary (off-by-1 targets due to opcode size mismatches).
        # Only do this for the top-level instruction list.
        if insns is self.insns:
            for off in sorted(self.labels):
                if off not in emitted_labels:
                    lines.append("")
                    lines.append("%s:" % self._label_name(off))

        return '\n'.join(lines)

    def _ind(self, n):
        return '    ' * n

    def _decompile_function_body(self, obj_info, indent):
        """Recursively decompile a nested function body."""
        obj_name = obj_info['name']
        nargs = obj_info['nargs']
        bc = obj_info['bc']
        nested_atoms = obj_info['nested_atoms']
        sub_scripts = obj_info['sub_scripts']

        # Merge nested atoms with parent atoms for proper scope resolution.
        # Nested functions reference both their own atoms AND parent-scope atoms.
        merged_atoms = list(nested_atoms) if nested_atoms else []
        parent_start_idx = len(merged_atoms)
        merged_atoms.extend(self.parent_atoms)
        atoms_used = merged_atoms

        # Disassemble with correct atoms
        insns, stopped = JSCReader().disasm(bc, atoms_used)

        # Build arg list
        args = ', '.join('arg%d' % i for i in range(nargs)) if nargs > 0 else ''

        # Decompile body
        decomp = JSCDecompiler(insns, atoms_used, sub_scripts, self.fname, atoms_used)
        decomp._build_labels(insns)
        body_lines = []
        decomp._decompile_insns(insns, body_lines, 0)
        body_code = '\n'.join(body_lines)

        # Format: function name(args) { body }
        indent_str = self._ind(indent)
        result = "%sfunction %s(%s) {\n%s\n%s}" % (
            indent_str, obj_name, args,
            self._ind(indent + 1) + body_code.replace('\n', '\n' + self._ind(indent + 1)),
            indent_str
        )
        return result

    def _exec_insn(self, off, b, name, base, fmt, raw, value, atom,
                   stack, lines, indent, insns, idx, in_with=False, init_stack=None):

        # === STOP ===
        if base in ('STOP',):
            stack.clear()
            return 'stop'

        # === NOP ===
        if base == 'NOP':
            return None

        # === PUSH ===
        if base == 'PUSH':
            stack.append('undefined')
            return None

        # === POP / POPV ===
        if base == 'POP':
            if stack: stack.pop()
            return None
        if base == 'POPV':
            if stack:
                val = stack.pop()
                if val != 'undefined':
                    lines.append(self._ind(indent) + "%s;" % val)
            return None
        if base == 'POPN' and isinstance(value, int):
            for _ in range(min(value, len(stack))):
                stack.pop()
            return None

        # === DUP / DUP2 / SWAP / PICK ===
        if base == 'DUP':
            if stack: stack.append(self._peek(stack))
            return None
        if base == 'DUP2':
            if len(stack) >= 2:
                stack.append(stack[-2])
                stack.append(self._peek(stack))
            return None
        if base == 'SWAP':
            if len(stack) >= 2:
                stack[-1], stack[-2] = stack[-2], stack[-1]
            return None
        if base == 'PICK':
            return None

        # === OBJTOP ===
        if base == 'OBJTOP':
            return None

        # === FORARG / FORLOCAL / GETARG / GETLOCAL ===
        if base in ('FORARG', 'FORLOCAL') and isinstance(value, int):
            if value > 10000:
                return None
            prefix = 'arg' if base == 'FORARG' else 'local'
            stack.append('%s_%d' % (prefix, value))
            return None
        if base == 'GETARG' and isinstance(value, int):
            stack.append('arg%d' % value)
            return None
        if base == 'GETLOCAL' and isinstance(value, int):
            stack.append('local_%d' % value)
            return None
        if base in ('SETARG', 'SETLOCAL', 'SETLOCALPOP'):
            self._pop(stack)
            return None

        # === ARGSUB (138) ===
        if base == 'ARGSUB' and isinstance(value, int):
            stack.append('arg%d' % value)
            return None

        # === CALLEE ===
        if base == 'CALLEE':
            stack.append('__callee__')
            return None

        # === ARGUMENTS ===
        if base == 'ARGUMENTS':
            stack.append('arguments')
            return None

        # === Literals ===
        if base == 'ZERO': stack.append('0'); return None
        if base == 'ONE': stack.append('1'); return None
        if base == 'NULL': stack.append('null'); return None
        if base == 'THIS': stack.append('this'); return None
        if base == 'TRUE': stack.append('true'); return None
        if base == 'FALSE': stack.append('false'); return None
        if base in ('UINT16', 'UINT24') and isinstance(value, int):
            stack.append(str(value)); return None
        if base == 'INT8' and isinstance(value, int):
            stack.append(str(value)); return None
        if base == 'INT32': return None

        # === NAME / GETGNAME / CALLNAME ===
        if base == 'NAME' and atom is not None:
            if self._is_debug_marker(atom) or self._is_version_string(atom):
                stack.append(_js_string(atom))
            else:
                stack.append(atom)
            return None
        if base == 'NAME':
            stack.append('name_%d' % (value if isinstance(value, int) else 0))
            return None
        if base == 'GETGNAME' and atom is not None:
            stack.append(atom); return None
        if base == 'CALLNAME' and atom is not None:
            stack.append(atom); return None
        if base == 'CALLGNAME' and atom is not None:
            stack.append(atom); return None
        if base == 'BINDNAME' and atom is not None:
            stack.append(atom); return None
        if base == 'BINDGNAME' and atom is not None:
            stack.append(atom); return None

        # === STRING literal ===
        if base == 'STRING' and atom is not None:
            stack.append(_js_string(atom))
            return None
        if base == 'STRING':
            stack.append('"?"')
            return None

        # === XMLCOMMENT (repurposed as string) ===
        if base == 'XMLCOMMENT' and atom is not None:
            stack.append(_js_string(atom))
            return None
        if base == 'XMLCOMMENT':
            stack.append('"?"'); return None

        # === XMLCDATA / XMLPI ===
        if base in ('XMLCDATA', 'XMLPI') and atom is not None:
            stack.append(_js_string(atom))
            return None

        # === DOUBLE ===
        if base == 'DOUBLE' and atom is not None:
            stack.append(atom)
            return None

        # === REGEXP ===
        if base == 'REGEXP' and value is not None:
            stack.append('/regexp_%d/' % value)
            return None
        if base == 'REGEXP' and atom is not None:
            stack.append('/%s/' % atom)
            return None

        # === GETTHISPROP ===
        if base == 'GETTHISPROP' and atom is not None:
            stack.append("this.%s" % atom); return None

        # === GETARGPROP / GETLOCALPROP (JOF_SLOTATOM) ===
        if base == 'GETARGPROP' and atom is not None:
            stack.append("arg_%d.%s" % (value if value is not None else 0, atom))
            return None
        if base == 'GETLOCALPROP' and atom is not None:
            stack.append("local_%d.%s" % (value if value is not None else 0, atom))
            return None

        # === CALLPROP / GETXPROP ===
        if base in ('CALLPROP', 'GETXPROP') and atom is not None:
            obj = self._pop(stack)
            stack.append("%s.%s" % (obj, atom))
            return None

        # === GETPROP ===
        if base == 'GETPROP' and atom is not None:
            obj = self._pop(stack)
            stack.append("%s.%s" % (obj, atom))
            return None
        if base == 'GETPROP':
            obj = self._pop(stack)
            stack.append("%s.%s" % (obj, 'UNKNOWN'))
            return None

        # === GETELEM ===
        if base == 'GETELEM':
            key = self._pop(stack)
            obj = self._pop(stack)
            stack.append("%s[%s]" % (obj, key))
            return None

        # === LENGTH ===
        if base == 'LENGTH':
            obj = self._pop(stack)
            stack.append("%s.length" % obj)
            return None

        # === CALL ===
        if base == 'CALL' and isinstance(value, int):
            nargs = value
            args_list = []
            for _ in range(nargs):
                args_list.insert(0, self._pop(stack))
            func = self._pop(stack)
            stack.append("%s(%s)" % (func, ', '.join(args_list)))
            return None

        # === CALLARG / CALLLOCAL ===
        if base in ('CALLARG', 'CALLLOCAL') and isinstance(value, int):
            prefix = 'arg' if base == 'CALLARG' else 'local'
            func = self._pop(stack)
            stack.append("%s(%s_%d)" % (func, prefix, value))
            return None

        # === NEW ===
        if base == 'NEW' and isinstance(value, int):
            nargs = value
            args_list = []
            for _ in range(nargs):
                args_list.insert(0, self._pop(stack))
            ctor = self._pop(stack)
            stack.append("new %s(%s)" % (ctor, ', '.join(args_list)))
            return None

        # === EVAL / FUNAPPLY / FUNCALL ===
        if base == 'EVAL' and isinstance(value, int):
            nargs = value
            args_list = []
            for _ in range(nargs):
                args_list.insert(0, self._pop(stack))
            stack.append("eval(%s)" % ', '.join(args_list))
            return None
        if base == 'FUNAPPLY' and isinstance(value, int):
            nargs = value
            args_list = []
            for _ in range(nargs):
                args_list.insert(0, self._pop(stack))
            func = self._pop(stack)
            stack.append("%s.apply(%s)" % (func, ', '.join(args_list)))
            return None
        if base == 'FUNCALL' and isinstance(value, int):
            nargs = value
            args_list = []
            for _ in range(nargs):
                args_list.insert(0, self._pop(stack))
            func = self._pop(stack)
            stack.append("%s.call(%s)" % (func, ', '.join(args_list)))
            return None
        if base == 'SETCALL':
            return None

        # === SETPROP ===
        if base == 'SETPROP' and atom is not None:
            val = self._pop(stack)
            if in_with:
                lines.append(self._ind(indent) + "%s = %s;" % (atom, val))
            else:
                obj = self._pop(stack)
                lines.append(self._ind(indent) + "%s.%s = %s;" % (obj, atom, val))
            return None
        if base == 'SETPROP':
            val = self._pop(stack)
            if in_with:
                lines.append(self._ind(indent) + "%s = %s;" % (atom if atom else '?', val))
            else:
                obj = self._pop(stack)
                lines.append(self._ind(indent) + "%s[?] = %s;" % (obj, val))
            return None

        # === SETNAME / SETGNAME / SETMETHOD ===
        if base == 'SETNAME' and atom is not None:
            val = self._pop(stack)
            lines.append(self._ind(indent) + "%s = %s;" % (atom, val))
            return None
        if base == 'SETNAME':
            self._pop(stack)
            lines.append(self._ind(indent) + "// setname ?")
            return None
        if base == 'SETGNAME' and atom is not None:
            val = self._pop(stack)
            lines.append(self._ind(indent) + "%s = %s;" % (atom, val))
            return None
        if base == 'SETGNAME':
            self._pop(stack); return None
        if base == 'SETMETHOD' and atom is not None:
            val = self._pop(stack)
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "%s.%s = %s;" % (obj, atom, val))
            return None
        if base == 'SETMETHOD':
            val = self._pop(stack)
            obj = self._pop(stack)
            return None

        # === SETCONST ===
        if base == 'SETCONST':
            val = self._pop(stack)
            if atom is not None:
                if in_with:
                    lines.append(self._ind(indent) + "%s = %s;" % (atom, val))
                elif stack:
                    obj = self._pop(stack)
                    lines.append(self._ind(indent) + "%s.%s = %s;" % (obj, atom, val))
                else:
                    lines.append(self._ind(indent) + "%s = %s;" % (atom, val))
            else:
                lines.append(self._ind(indent) + "// setconst ?")
            return None

        # === SETELEM ===
        if base == 'SETELEM':
            val = self._pop(stack)
            key = self._pop(stack)
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "%s[%s] = %s;" % (obj, key, val))
            return None

        # === Declaration ===
        if base == 'DEFVAR' and atom is not None:
            lines.append(self._ind(indent) + "var %s;" % atom)
            return None
        if base == 'DEFCONST' and atom is not None:
            lines.append(self._ind(indent) + "const %s;" % atom)
            return None

        # === Delete ===
        if base == 'DELNAME' and atom is not None:
            lines.append(self._ind(indent) + "delete %s;" % atom)
            return None
        if base == 'DELNAME':
            lines.append(self._ind(indent) + "// delname ?")
            return None
        if base == 'DELPROP' and atom is not None:
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "delete %s.%s;" % (obj, atom))
            return None
        if base == 'DELPROP':
            self._pop(stack); return None
        if base == 'DELELEM':
            key = self._pop(stack)
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "delete %s[%s];" % (obj, key))
            return None

        # === Binary operators ===
        if b in BINOP_SYM:
            right = self._pop(stack)
            left = self._pop(stack)
            op_sym = BINOP_SYM[b]
            stack.append("(%s %s %s)" % (left, op_sym, right))
            return None

        # === Unary operators ===
        if b in UNOP_SYM:
            val = self._pop(stack)
            sym = UNOP_SYM[b]
            if sym in ('typeof', 'void'):
                stack.append("%s(%s)" % (sym, val))
            else:
                stack.append("%s%s" % (sym, val))
            return None

        # === INC/DEC ===
        if base == 'INCNAME' and atom is not None:
            lines.append(self._ind(indent) + "++%s;" % atom); return None
        if base == 'DECNAME' and atom is not None:
            lines.append(self._ind(indent) + "--%s;" % atom); return None
        if base == 'NAMEINC' and atom is not None:
            lines.append(self._ind(indent) + "%s++;" % atom); return None
        if base == 'NAMEDEC' and atom is not None:
            lines.append(self._ind(indent) + "%s--;" % atom); return None
        if base == 'INCPROP' and atom is not None:
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "++%s.%s;" % (obj, atom)); return None
        if base == 'DECPROP' and atom is not None:
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "--%s.%s;" % (obj, atom)); return None
        if base == 'PROPINC' and atom is not None:
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "%s.%s++;" % (obj, atom)); return None
        if base == 'PROPDEC' and atom is not None:
            obj = self._pop(stack)
            lines.append(self._ind(indent) + "%s.%s--;" % (obj, atom)); return None
        if base in ('INCNAME', 'DECNAME', 'NAMEINC', 'NAMEDEC'):
            lines.append(self._ind(indent) + "// inc/dec ?")
            return None
        if base in ('INCELEM', 'DECELEM', 'ELEMINC', 'ELEMDEC',
                     'INCARG','DECARG','ARGINC','ARGDEC',
                     'INCLOCAL','DECLOCAL','LOCALINC','LOCALDEC',
                     'INCGNAME','DECGNAME','GNAMEINC','GNAMEDEC'):
            return None
        if base in ('INCPROP', 'DECPROP', 'PROPINC', 'PROPDEC'):
            self._pop(stack); return None

        # === RETURN ===
        if base == 'RETURN':
            tos = self._peek(stack)
            if tos != 'undefined' or True:
                lines.append(self._ind(indent) + "return %s;" % tos)
            return 'skip_to_label'
        if base == 'RETRVAL':
            tos = self._peek(stack)
            lines.append(self._ind(indent) + "return %s;" % tos)
            return None
        if base == 'SETRVAL':
            return None

        # === YIELD ===
        if base == 'YIELD':
            lines.append(self._ind(indent) + "yield;")
            return None

        # === THROW ===
        if base == 'THROW':
            expr = self._pop(stack)
            lines.append(self._ind(indent) + "throw %s;" % expr)
            return None

        # === WITH ===
        if base == 'ENTERWITH':
            obj = self._pop(stack) if stack else 'UNKNOWN'
            lines.append(self._ind(indent) + "with (%s) {" % obj)
            return 'skip_with_block'
        if base == 'LEAVEWITH':
            if in_with:
                lines.append(self._ind(indent) + "}")
            return None

        # === TRY ===
        if base == 'TRY':
            lines.append(self._ind(indent) + "try {")
            return None
        if base == 'FINALLY':
            lines.append(self._ind(indent) + "} finally {")
            return None
        if base == 'EXCEPTION':
            stack.append('__exception__')
            return None
        if base in ('GOSUB', 'RETSUB'):
            return None

        # === Object/Array literals ===
        if base == 'NEWINIT':
            if init_stack is not None:
                init_stack.append('{}')
            return None
        if base == 'NEWARRAY':
            stack.append('[]'); return None
        if base == 'NEWOBJECT':
            if init_stack is not None:
                init_stack.append('{}')
            return None
        if base == 'ENDINIT':
            completed = self._pop(init_stack) if init_stack else self._pop(stack)
            if completed == '{}' or completed is None:
                completed = '{}'
            elif ':' in str(completed) and not str(completed).startswith('{'):
                if init_stack and str(init_stack[-1]) == '{}':
                    stack.append(completed)
                    return None
                completed = '{%s}' % completed
            stack.append(completed)
            return None
        if base == 'INITPROP' and atom is not None:
            val = self._pop(stack)
            if init_stack and len(init_stack) > 0:
                cur = str(init_stack[-1])
                if cur == '{}':
                    init_stack[-1] = '%s: %s' % (_js_string(atom), val)
                else:
                    init_stack[-1] = '%s, %s: %s' % (cur, _js_string(atom), val)
            else:
                lines.append(self._ind(indent) + "%s[%s] = %s;" % (self._pop(stack), _js_string(atom), val))
                if init_stack is not None:
                    init_stack.append(val)
            return None
        if base == 'INITMETHOD' and atom is not None:
            val = self._pop(stack)
            if init_stack and len(init_stack) > 0:
                cur = str(init_stack[-1])
                if cur == '{}':
                    init_stack[-1] = '%s: %s' % (atom, val)
                else:
                    init_stack[-1] = '%s, %s: %s' % (cur, atom, val)
            return None
        if base == 'INITELEM':
            return None
        if base == 'HOLE':
            return None

        # === LAMBDA / Function ===
        # Use the operand 'value' as the index into nested_objects (Cocos2d-x dialect:
        # byte 4 of the 5-byte LAMBDA instruction is the obj index, available as 'value').
        # Fall back to sequential _obj_index if value is missing.
        def _pick_obj(value):
            if value is not None and 0 <= value < len(self.nested_objects):
                return self.nested_objects[value]
            if self._obj_index < len(self.nested_objects):
                obj = self.nested_objects[self._obj_index]
                self._obj_index += 1
                return obj
            return None

        if base in ('LAMBDA', 'LAMBDA_FC', 'LAMBDA_DBGFC'):
            obj_info = _pick_obj(value)
            if obj_info is not None:
                if _is_jsb_binding(obj_info['bc']):
                    stack.append('function() {/* JSB native binding */}')
                    return None
                func_body = self._decompile_function_body(obj_info, 0)
                stack.append(func_body)
                return None
            stack.append('function() {/*...*/}')
            return None
        if base in ('DEFFUN', 'DEFFUN_FC', 'DEFFUN_DBGFC'):
            obj_info = _pick_obj(value)
            if obj_info is not None:
                if _is_jsb_binding(obj_info['bc']):
                    lines.append(self._ind(indent) + "// JSB native binding: %s" % obj_info['name'])
                    return None
                func_body = self._decompile_function_body(obj_info, 0)
                lines.append(func_body)
                return None
            lines.append(self._ind(indent) + "// function def")
            return None
        if base in ('DEFLOCALFUN', 'DEFLOCALFUN_FC', 'DEFLOCALFUN_DBGFC'):
            obj_info = _pick_obj(value)
            if obj_info is not None:
                if _is_jsb_binding(obj_info['bc']):
                    lines.append(self._ind(indent) + "// JSB native binding: %s" % obj_info['name'])
                    return None
                func_body = self._decompile_function_body(obj_info, 0)
                lines.append(self._ind(indent) + func_body)
                return None
            lines.append(self._ind(indent) + "// local function def")
            return None
        if base in ('OBJECT', 'BLOCKCHAIN'):
            obj_info = _pick_obj(value)
            lines.append(self._ind(indent) + "// object def: %s" % (obj_info['name'] if obj_info else '?'))
            return None

        # === Jump/branch ===
        fl_insn = get_fl(fmt) if fmt else 3
        next_off = off + fl_insn

        if base == 'GOTO' and isinstance(value, int):
            if value == next_off or value == off:
                return None
            self.labels.add(value)
            target_name = self._label_name(value)
            lines.append(self._ind(indent) + "goto %s;" % target_name)
            return None

        if base == 'IFEQ' and isinstance(value, int):
            if value == next_off or value == off:
                self._pop(stack)
                return None
            cond = self._pop(stack)
            # Check for out-of-range target (beyond bytecodes → skip rest of function)
            bc_end = insns[-1][0] + 3 if insns else 0
            if value >= bc_end:
                lines.append(self._ind(indent) + "if (%s) {" % cond)
                return 'out_if'
            self.labels.add(value)
            target_name = self._label_name(value)
            lines.append(self._ind(indent) + "if (!(%s)) goto %s;" % (cond, target_name))
            return None

        if base == 'IFNE' and isinstance(value, int):
            if value == next_off or value == off:
                self._pop(stack)
                return None
            cond = self._pop(stack)
            # Check for out-of-range target
            bc_end = insns[-1][0] + 3 if insns else 0
            if value >= bc_end:
                lines.append(self._ind(indent) + "if (!(%s)) {" % cond)
                return 'out_if'
            self.labels.add(value)
            target_name = self._label_name(value)
            lines.append(self._ind(indent) + "if (%s) goto %s;" % (cond, target_name))
            return None

        # === AND/OR short-circuit ===
        if base == 'AND' and isinstance(value, int):
            if value == next_off or value == off:
                return None
            self._pop(stack)
            return None
        if base == 'OR' and isinstance(value, int):
            if value == next_off or value == off:
                return None
            self._pop(stack)
            return None

        # === Extended jumps ===
        if base in ('GOTOX', 'IFEQX', 'IFNEX', 'ORX', 'ANDX', 'IFPRIMTOP'):
            return None

        # === Case/Switch ===
        if base in ('CASE', 'DEFAULT', 'CONDSWITCH',
                     'TABLESWITCH', 'LOOKUPSWITCH',
                     'TABLESWITCHX', 'LOOKUPSWITCHX',
                     'CASEX', 'DEFAULTX'):
            return None

        # === Iterator ===
        if base in ('ITER', 'MOREITER', 'ENDITER', 'ENUMELEM',
                     'FORNAME', 'FORPROP', 'FORELEM', 'FORGNAME',
                     'ENUMCONSTELEM'):
            return None

        # === Blocks ===
        if base in ('ENTERBLOCK', 'LEAVEBLOCK', 'LEAVEBLOCKEXPR'):
            return None

        # === Index base ===
        if base in ('INDEXBASE', 'INDEXBASE1', 'INDEXBASE2', 'INDEXBASE3',
                     'RESETBASE', 'RESETBASE0'):
            return None

        # === Debug ===
        if base == 'DEBUGGER':
            lines.append(self._ind(indent) + "debugger;")
            return None
        if base in ('LINENO', 'NOTRACE', 'TRACE', 'GETUPVAR_DBG', 'CALLUPVAR_DBG',
                     'GETFCSLOT', 'CALLFCSLOT', 'TRAP'):
            return None

        # === Misc ===
        if base in ('PRIMTOP', 'GENERATOR', 'TOXML','TOXMLLIST','XMLTAGEXPR','XMLELTEXPR',
                     'STARTXML','STARTXMLEXPR','CALLELEM','CALLXMLNAME','TYPEOFEXPR','ANYNAME',
                     'QNAMEPART','QNAMECONST','QNAME','TOATTRNAME','TOATTRVAL',
                     'ADDATTRNAME','ADDATTRVAL','BINDXMLNAME','SETXMLNAME',
                     'XMLNAME','DESCENDANTS','FILTER','ENDFILTER',
                     'GETFUNNS','DEFXMLNS','NULLBLOCKCHAIN','UNBRAND','UNBRANDTHIS',
                     'SHARPINIT','USESHARP','DEFSHARP','IMACOP','THROWING','GETTER','SETTER',
                     'DELDESC','ARRAYPUSH',
                     'BACKPATCH','BACKPATCH_POP','GOSUBX'):
            return None

        # === Cocos2d-x JSB custom opcodes (244-255) — JOF_BYTE no-ops ===
        if base.startswith('JSB_'):
            return None

        # === Unknown/Truncated ===
        if base.startswith('TRUNC_') or base.startswith('UNKNOWN_'):
            lines.append(self._ind(indent) + "// %s at 0x%x" % (name, off))
            return None

        # Fallback
        lines.append(self._ind(indent) + "// unhandled: %s" % name)
        return None


def _infer_jsb_structure(atoms, bc, rel_path):
    """Extract structured data from JSB inline format root bytecodes.

    JSB inline files store UTF-16LE string data in atom tables, with the
    bytecode section containing inline strings instead of real SM opcodes.
    This function heuristically reconstructs the data structure from atoms.
    """
    lines = []
    lines.append("// JSB inline data — atom-based extraction (not SM bytecode)")

    if not atoms:
        lines.append("// No atoms found")
        return '\n'.join(lines)

    # Detect assignment target from first few atoms
    # Common pattern: ['xs', 'Cfg', 'System', 'config_name'] → this.Cfg.System.config_name
    # Other patterns: ['xs', 'Module', 'name'] → this.Module.name
    #                ['cc', 'constant1', 'constant2', ...] → cc.constant1 = ...
    target_parts = []
    data_start = 0

    if len(atoms) >= 2 and atoms[0] == 'xs':
        target_parts = ['this'] + atoms[1:4] if len(atoms) >= 4 else ['this'] + atoms[1:]
        data_start = len(target_parts)
    elif len(atoms) >= 1 and atoms[0] in ('cc', 'cp', 'require'):
        target_parts = [atoms[0]]
        data_start = 1
        # For 'require' files, atoms[1:] might be require paths
        if atoms[0] == 'require' and len(atoms) > 1:
            lines.append('')
            lines.append('// Required modules:')
            for i in range(1, len(atoms)):
                lines.append('//   require(%s);' % _js_string(atoms[i]))
            return '\n'.join(lines)
    else:
        target_parts = [atoms[0]] if atoms else []
        data_start = 1

    target = '.'.join(target_parts) if target_parts else None
    data_atoms = atoms[data_start:]

    lines.append('')

    if target:
        lines.append('// Assignment target: %s' % target)
    lines.append('// Data entries: %d atoms starting at index %d' % (len(data_atoms), data_start))
    lines.append('')

    # Try to detect record structure: look for repeating key patterns
    # If atoms at positions 0,3,6,9,... are the same (field names repeating),
    # it's an array of records
    record_size = None
    if len(data_atoms) >= 6:
        first_keys = tuple(data_atoms[:3])
        second_keys = tuple(data_atoms[3:6])
        if first_keys == second_keys:
            # Possible repeating record: check if pattern continues
            record_size = len(first_keys)
            if len(data_atoms) >= record_size * 2:
                third_keys = tuple(data_atoms[record_size*2:record_size*3])
                if third_keys == first_keys and len(data_atoms) >= record_size * 3:
                    pass  # confirmed: 3+ records with same keys
                elif len(data_atoms) >= record_size * 2:
                    pass  # at least 2 records

    # Try key-value pair detection: if atoms alternate between key-like and value-like
    # Key-like: contains '_' or is all lowercase/alpha
    is_kv = False
    if len(data_atoms) >= 4 and len(data_atoms) % 2 == 0:
        keys = [data_atoms[i] for i in range(0, len(data_atoms), 2)]
        all_keys = all(
            ('_' in k or k[0].islower() or k.isalpha()) and not k[0].isdigit()
            for k in keys if k
        )
        if all_keys:
            is_kv = True

    # Format output
    if record_size and record_size > 1:
        lines.append('// Detected: array of %d records, %d fields each' % (
            len(data_atoms) // record_size, record_size))
        lines.append('// Fields: %s' % ', '.join(data_atoms[:record_size]))
        if target:
            lines.append('%s = [' % target)
            for rec_idx in range(0, len(data_atoms), record_size):
                rec = data_atoms[rec_idx:rec_idx + record_size]
                if len(rec) == record_size:
                    fields = ', '.join('%s: %s' % (data_atoms[i], _js_string(rec[i]))
                                      for i in range(record_size))
                    lines.append('    {%s},' % fields)
            lines.append('];')
        else:
            lines.append('[')
            for rec_idx in range(0, len(data_atoms), record_size):
                rec = data_atoms[rec_idx:rec_idx + record_size]
                if len(rec) == record_size:
                    fields = ', '.join('%s: %s' % (data_atoms[i], _js_string(rec[i]))
                                      for i in range(record_size))
                    lines.append('    {%s},' % fields)
            lines.append('];')

    elif is_kv:
        if target:
            lines.append('%s = {' % target)
            for i in range(0, len(data_atoms), 2):
                key = data_atoms[i]
                val = data_atoms[i+1] if i+1 < len(data_atoms) else 'null'
                lines.append('    %s: %s,' % (_js_string(key), _js_string(val)))
            lines.append('};')
        else:
            lines.append('{')
            for i in range(0, len(data_atoms), 2):
                key = data_atoms[i]
                val = data_atoms[i+1] if i+1 < len(data_atoms) else 'null'
                lines.append('    %s: %s,' % (_js_string(key), _js_string(val)))
            lines.append('};')

    else:
        # Generic: output as array */
        if target:
            lines.append('%s = [' % target)
        else:
            lines.append('[')

        for i, a in enumerate(data_atoms):
            lines.append('    %s,  // [%d]' % (_js_string(a), data_start + i))

        lines.append('];')

    return '\n'.join(lines)


def process_all():
    reader = JSCReader()
    os.makedirs(OUT_DIR, exist_ok=True)

    # Walk all JSC directories
    all_files = []
    for base_dir in (JSC_DIR, JSC_DIR2):
        if not os.path.isdir(base_dir):
            continue
        for root, dirs, fnames in os.walk(base_dir):
            for f in fnames:
                if f.endswith('.jsc'):
                    if base_dir == JSC_DIR:
                        rel_path = os.path.relpath(os.path.join(root, f), os.path.dirname(base_dir))
                    else:
                        rel_path = os.path.relpath(os.path.join(root, f), os.path.dirname(base_dir))
                    all_files.append((root, os.path.basename(f), rel_path))

    all_files.sort(key=lambda x: x[2])

    total = len(all_files)
    ok = 0
    jsb_count = 0
    errors = []

    for root_dir, fname, rel_path in all_files:
        full_path = os.path.join(root_dir, fname)

        try:
            bc, atoms, field1, field5, natoms, nobjects, objects, xdr = reader.analyze_jsc(full_path)
        except Exception as e:
            errors.append((rel_path, str(e)))
            continue

        out_rel = rel_path.replace('.jsc', '.js')
        outpath = os.path.join(OUT_DIR, out_rel)
        os.makedirs(os.path.dirname(outpath), exist_ok=True)

        is_jsb = _is_jsb_binding(bc)

        if is_jsb:
            # JSB inline data — skip SM disasm/decompile entirely.
            # Atom extraction always produces correct output for these files.
            js_code = _infer_jsb_structure(atoms, bc, rel_path)
            jsb_count += 1

            with open(outpath, 'w', encoding='utf-8') as f:
                f.write("// Extracted from %s\n" % rel_path)
                f.write("// Atoms: %d/%d, Objects: %d\n" % (len(atoms), natoms, nobjects))
                if nobjects > 0:
                    f.write("// Note: %d objects present but not reconstructed\n" % nobjects)
                f.write("\n")
                f.write(js_code)
        else:
            # Genuine SM bytecode — run full decompilation pipeline.
            try:
                instructions, stopped = reader.disasm(bc, atoms)
            except Exception as e:
                errors.append((rel_path, "disasm: " + str(e)))
                continue

            decomp = JSCDecompiler(instructions, atoms, objects, fname, atoms)
            try:
                js_code = decomp.decompile()
            except Exception as e:
                errors.append((rel_path, "decompile: " + str(e)))
                continue

            with open(outpath, 'w', encoding='utf-8') as f:
                f.write("// Decompiled from %s\n" % rel_path)
                f.write("// Instructions: %d, Atoms: %d/%d, Objects: %d\n\n" % (
                    len(instructions), len(atoms), natoms, nobjects))
                f.write(js_code)

        ok += 1
        if ok % 100 == 0:
            print("[%d/%d] %s" % (ok, total, rel_path))


    print("\nDone: %d/%d files" % (ok, total))
    print("  JSB inline data: %d" % jsb_count)
    print("  SM bytecode: %d" % (ok - jsb_count))
    if errors:
        print("  Errors: %d" % len(errors))
        for rel_path, err in errors[:10]:
            print("    %s: %s" % (rel_path, err))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="JSC → JS decompiler v8")
    parser.add_argument('--src-jsc', default=JSC_DIR, help='src_jsc directory (default: %(default)s)')
    parser.add_argument('--data-jsc', default=JSC_DIR2, help='data_cn_jsc directory (default: %(default)s)')
    parser.add_argument('--out', default=OUT_DIR, help='output directory (default: %(default)s)')
    parser.add_argument('--single', help='decompile a single .jsc file (path) and print to stdout')
    args = parser.parse_args()
    JSC_DIR = args.src_jsc
    JSC_DIR2 = args.data_jsc
    OUT_DIR = args.out
    if args.single:
        # Single-file mode for testing
        reader = JSCReader()
        bc, atoms, field1, field5, natoms, nobjects, objects, xdr = reader.analyze_jsc(args.single)
        if _is_jsb_binding(bc):
            inferred = _infer_jsb_structure(atoms, bc, os.path.basename(args.single))
            print(inferred)
        else:
            insns_result = reader.disasm(bc, atoms, nested_objects=objects)
            insns = insns_result[0]
            decomp = JSCDecompiler(insns, atoms, nested_objects=objects, fname=args.single)
            print(decomp.decompile())
    else:
        process_all()
