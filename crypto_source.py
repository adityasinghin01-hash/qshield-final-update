"""Structural source evidence for Python and lexical call evidence for JS/TS.

Python uses ast and tokenize. JS uses token spans and balanced call arguments;
it deliberately reports lexical evidence, not an AST or runtime guarantee.
Only bounded literal evaluation is used; repository code is never executed.
"""
import ast
import io
import re
import tokenize


_MAX_LITERAL_LENGTH = 4096
_MAX_LITERAL_INTEGER = 2**63 - 1


def _literal(node, bindings, depth=0, expected=None):
    """Resolve bounded literals; reject multiplication before allocating its result.

    A callable binding resolver evaluates each reference in its own AST scope.
    Numeric consumers request int so byte/string expressions are never expanded.
    """
    if depth > 8:
        return None
    if isinstance(node, ast.Name):
        if callable(bindings):
            return bindings(node, depth + 1, expected)
        return _literal(bindings.get(node.id), bindings, depth + 1, expected)
    if isinstance(node, ast.Constant):
        value = node.value
        if expected is not None and type(value) is not expected:
            return None
        if type(value) is int and abs(value) <= _MAX_LITERAL_INTEGER:
            return value
        if isinstance(value, (str, bytes)) and len(value) <= _MAX_LITERAL_LENGTH:
            return value
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)) and expected in (None, int):
        value = _literal(node.operand, bindings, depth+1, int)
        return (-value if isinstance(node.op, ast.USub) else value) if value is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        a = _literal(node.left, bindings, depth+1, expected)
        b = _literal(node.right, bindings, depth+1, int)
        if isinstance(a, (str, bytes)) and type(b) is int and 0 <= b <= _MAX_LITERAL_LENGTH and len(a) * b <= _MAX_LITERAL_LENGTH:
            return a * b
        if type(a) is int and type(b) is int and abs(a) <= _MAX_LITERAL_INTEGER // max(1, abs(b)):
            return a * b
    if isinstance(node, ast.Call) and expected is None:
        name = ast.unparse(node.func)
        if name in ('os.urandom', 'secrets.token_bytes') and node.args:
            size = _literal(node.args[0], bindings, depth+1, int)
            if type(size) is int and 0 <= size <= _MAX_LITERAL_LENGTH:
                return b'\0' * size
    return None


def _parameters(text, key=None):
    params = {}
    m = re.search(r'\b(?:key_size|modulusLength)\s*[=:]\s*(\d+)\b', text)
    if m:
        params['key_bits'] = int(m.group(1))
    curve = re.search(r'(?:SECP|secp|prime|P-)(256|384|521)(?:R1|r1|v1)?', text)
    if curve:
        params['curve'] = f'P-{curve.group(1)}'
    if isinstance(key, bytes):
        params['key_bits'] = len(key) * 8
    cipher = re.search(r'\baes[-_](128|192|256)[-_](gcm|cbc|ecb|ctr|ccm)\b', text, re.I)
    if cipher:
        params.update(key_bits=int(cipher.group(1)), mode=cipher.group(2).upper())
    return params


def _extra_call(name, text):
    """Return explicit identities not covered by the legacy pattern catalog."""
    low = name.lower()
    if name == 'PBKDF2HMAC':
        return 'PBKDF2-HMAC', 'Password-Based Key Derivation', 'QUANTUM_RESISTANT'
    if low == 'hashlib.scrypt':
        return 'scrypt', 'Password-Based Key Derivation', 'QUANTUM_RESISTANT'
    if name == 'dsa.generate_private_key':
        return 'DSA', 'Digital Signature Scheme', 'CRITICAL_VULNERABLE'
    if name in ('dh.generate_parameters', 'diffie_hellman.generate_parameters'):
        return 'Diffie-Hellman', 'Key Agreement', 'CRITICAL_VULNERABLE'
    if name in ('algorithms.AES', 'AES.new'):
        return 'AES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low in ('algorithms.tripledes', 'des3.new'):
        return '3DES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low in ('algorithms.arc4', 'arc4.new'):
        return 'RC4', 'Symmetric Encryption', 'NOT_APPLICABLE'
    if low == 'des.new':
        return 'DES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low == 'modes.cbc':
        return 'Block cipher CBC', 'Block Cipher Mode', 'NOT_APPLICABLE'
    if low in ('crypto.createcipheriv', 'crypto.createdecipheriv'):
        m = re.search(r"\(\s*['\"]([^'\"]+)", text)
        return (m.group(1) if m else 'Unknown-Cipher'), 'Symmetric Encryption', 'MODERATE_IMPACT'
    if re.fullmatch(r'mlkem(?:512|768|1024)(?:privatekey)?\.generate', low):
        bits = re.search(r'(512|768|1024)', low).group(1)
        return 'ML-KEM-'+bits, 'Key Agreement', 'QUANTUM_RESISTANT'
    if low in ('ed448privatekey.generate', 'ed448.ed448privatekey.generate'):
        return 'Ed448', 'Digital Signature', 'CRITICAL_VULNERABLE'
    if name == 'ChaCha20Poly1305':
        return 'ChaCha20-Poly1305', 'Authenticated Symmetric Encryption', 'QUANTUM_RESISTANT'
    return None


def _emit_call(name, text, line, column, snippet, rules, params, evidence):
    results = []
    for rule in rules:
        if rule['match_type'].value in ('IMPORT_STATEMENT', 'EXPOSED_SECRET'):
            continue
        match = re.search(rule['pattern'], text, re.I)
        # A nested call is visited separately; don't duplicate it at its parent.
        if match and match.start() == 0:
            item = dict(rule=rule, line=line, column=column, snippet=snippet,
                        parameters=params, evidence=evidence)
            results.append(item)
    extra = _extra_call(name, text)
    if extra and not results:
        results.append(dict(identity=extra, line=line, column=column, snippet=snippet,
                            parameters=params, evidence=evidence))
    return results


def python_events(content, rules):
    events, diagnostics = [], []
    try:
        tree = ast.parse(content)
    except SyntaxError as err:
        return [], [f'Python parse error at line {err.lineno}; file not analyzed structurally.']
    # Scope-local symbol tables: only a single unconditional binding is trusted.
    # Every Store invalidates competing aliases, including loop/with/walrus writes.
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    scopes = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    tables = {}

    def scope_of(node):
        parent = parents.get(node)
        while parent is not None and not isinstance(parent, scopes):
            parent = parents.get(parent)
        return parent or tree

    def conditional(node, scope):
        parent = parents.get(node)
        while parent is not None and parent is not scope:
            if isinstance(parent, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                                   ast.With, ast.AsyncWith, ast.Match, ast.comprehension)):
                return True
            parent = parents.get(parent)
        return False

    def bind(scope, name, value, node, kind):
        tables.setdefault(scope, {}).setdefault(name, []).append((value, node, kind, conditional(node, scope)))

    for node in ast.walk(tree):
        scope = scope_of(node)
        if isinstance(node, ast.Import):
            for alias in node.names:
                bind(scope, alias.asname or alias.name.split('.')[0],
                     alias.name if alias.asname else alias.name.split('.')[0], node, 'import')
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bind(scope, alias.asname or alias.name, (node.module or '')+'.'+alias.name, node, 'import')
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            parent = parents.get(node)
            value = parent.value if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
            bind(scope, node.id, value, node, 'value')
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                bind(scope, root.id, None, node, 'namespace_mutation')
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(scope, node.name, None, node, 'definition')
        elif isinstance(node, ast.arg):
            bind(scope, node.arg, None, node, 'argument')
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(scope, node.name, None, node, 'exception')
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(scope, node.name, None, node, 'pattern_capture')
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(scope, node.rest, None, node, 'pattern_capture')
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(scope, name, None, node, 'scope_mutation')

    def lookup(name, context):
        scope = scope_of(context)
        # Python methods do not close over a class namespace. A class-local
        # import cannot establish an unqualified alias inside its methods.
        immediate_class = scope if isinstance(scope, ast.ClassDef) else None
        inaccessible_binding = False
        while True:
            if isinstance(scope, ast.ClassDef) and scope is not immediate_class:
                inaccessible_binding |= name in tables.get(scope, {})
                scope = scope_of(scope)
                continue
            entries = tables.get(scope, {}).get(name)
            if entries:
                if len(entries) != 1:
                    return None, 'uncertain'
                value, node, kind, uncertain = entries[0]
                if uncertain or kind not in ('value', 'import') or node.lineno > context.lineno:
                    return None, 'uncertain'
                return (value, kind, node), 'bound'
            if scope is tree:
                return None, 'uncertain' if inaccessible_binding else 'unbound'
            scope = scope_of(scope)

    def full_name(node, context, seen=()):
        if isinstance(node, ast.Attribute):
            root = full_name(node.value, context, seen)
            return root + '.' + node.attr if root else None
        if not isinstance(node, ast.Name) or node.id in seen or len(seen) > 8:
            return None
        binding, state = lookup(node.id, context)
        if state == 'uncertain':
            return None
        if state == 'unbound':
            return node.id
        value, kind, bound_node = binding
        if kind == 'import':
            return value
        return full_name(value, bound_node, seen+(node.id,)) if value is not None else None

    def canonical(node, context=None):
        full = full_name(node, context or node)
        if not full:
            return None
        if full.startswith(('cryptography.', 'Crypto.', 'Cryptodome.')):
            for prefix in ('rsa.', 'ec.', 'dsa.', 'dh.', 'x25519.', 'ed25519.', 'ed448.', 'mlkem.', 'padding.', 'modes.', 'algorithms.', 'RSA.', 'AES.', 'DES3.', 'DES.', 'ARC4.'):
                start = full.rfind('.'+prefix)
                if start >= 0:
                    return full[start+1:]
        if full.startswith('cryptography.'):
            parts = full.split('.')
            return '.'.join(parts[-2:]) if parts[-1] == 'generate' else parts[-1]
        return full

    def resolve_literal(reference, depth, expected):
        binding, state = lookup(reference.id, reference)
        if state != 'bound' or binding[1] != 'value':
            return None
        # The value AST remains attached to the original binding's lexical
        # scope. Recursive names are looked up there, never in the consumer.
        return _literal(binding[0], resolve_literal, depth, expected)

    def bound_expression(node, depth=0):
        if depth > 8:
            return None
        if not isinstance(node, ast.Name):
            return node
        binding, state = lookup(node.id, node)
        if state != 'bound' or binding[1] != 'value':
            return None
        return bound_expression(binding[0], depth+1)

    def scope_name(node):
        names, scope = [], scope_of(node)
        while scope is not tree:
            names.append(getattr(scope, 'name', '<lambda>'))
            scope = scope_of(scope)
        return '.'.join(reversed(names)) or '<module>'

    crypto_roots = {'hashlib','crypto','bcrypt','argon2','rsa','ec','AES','AESGCM','PBKDF2HMAC',
                    'algorithms','modes','dsa','dh','padding','cryptography','Crypto'}
    crypto_aliases = set(crypto_roots)
    for _ in range(8):
        previous = set(crypto_aliases)
        for table in tables.values():
            for alias, entries in table.items():
                for value, _, kind, _ in entries:
                    if kind == 'import' and isinstance(value, str) and value.split('.')[0] in crypto_roots:
                        crypto_aliases.add(alias)
                    elif isinstance(value, (ast.Name, ast.Attribute)) and not any(isinstance(n, ast.Call) for n in ast.walk(value)) and any(isinstance(n, ast.Name) and n.id in crypto_aliases for n in ast.walk(value)):
                        crypto_aliases.add(alias)
        if previous == crypto_aliases:
            break

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            text = ast.unparse(node)
            for rule in rules:
                if rule['match_type'].value == 'IMPORT_STATEMENT' and re.search(rule['pattern'], text, re.I):
                    events.append(dict(rule=rule, line=node.lineno, column=node.col_offset+1,
                                       snippet=text, parameters={}, evidence='python_ast'))
        if isinstance(node, ast.Call):
            name = canonical(node.func)
            if name is None:
                # Chained .digest()/.encode() calls are ordinary uses of an
                # already visited expression. Unknown aliases and dynamic
                # lookup of crypto APIs still require an explicit diagnostic.
                inner = node.func.value if isinstance(node.func, ast.Attribute) else None
                known_inner = isinstance(inner, ast.Call) and canonical(inner.func) is not None
                if not known_inner and any(isinstance(n, ast.Name) and n.id in crypto_aliases for n in ast.walk(node.func)):
                    diagnostics.append(f'Unresolved or reassigned call target at line {node.lineno}; no confident crypto identity inferred.')
                continue
            if name == 'getattr' and node.args and (canonical(node.args[0]) or '').split('.')[0] in crypto_roots:
                diagnostics.append(f'Dynamic crypto attribute lookup at line {node.lineno}; target is unresolved.')
            text = name + '(' + ', '.join([ast.unparse(a) for a in node.args] + [f'{k.arg}={ast.unparse(k.value)}' for k in node.keywords]) + ')'
            original = ast.get_source_segment(content, node) or text
            key = None
            if name in ('AESGCM', 'algorithms.AES', 'AES.new', 'ChaCha20Poly1305') and node.args:
                key = _literal(node.args[0], resolve_literal)
            params = {'key_bits': len(key)*8} if isinstance(key, bytes) else {}
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    curve = re.fullmatch(r'ec\.SECP(256|384|521)R1',canonical(child.func) or '',re.I)
                    if curve:
                        params['curve'] = 'P-'+curve.group(1)
                elif isinstance(child, ast.Attribute) and child.attr in ('MODE_ECB','MODE_CBC','MODE_GCM','MODE_CTR'):
                    params['mode'] = child.attr[5:]
            if name.endswith('RSA.generate') and node.args:
                bits = _literal(node.args[0], resolve_literal, expected=int)
                if type(bits) is int:
                    params['key_bits'] = bits
            # Keyword values may refer to bounded literals too.
            for kw in node.keywords:
                if kw.arg == 'key_size':
                    bits = _literal(kw.value, resolve_literal, expected=int)
                    if type(bits) is int:
                        params['key_bits'] = bits
            # Extract only named cost/digest settings; passwords and salts never enter evidence.
            def argument(index, keyword):
                return next((k.value for k in node.keywords if k.arg == keyword),
                            node.args[index] if len(node.args) > index else None)

            if name == 'hashlib.pbkdf2_hmac':
                digest = _literal(argument(0, 'hash_name'), resolve_literal, expected=str)
                if isinstance(digest, str) and digest.lower().replace('-', '') in ('sha1','sha256','sha512'):
                    params['digest'] = digest.lower().replace('-', '')
                count = _literal(argument(3, 'iterations'), resolve_literal, expected=int)
                if type(count) is int:
                    params['iterations'] = count
            elif name.endswith('PBKDF2HMAC'):
                digest = argument(0, 'algorithm')
                digest_name = canonical(digest.func) if isinstance(digest, ast.Call) else ''
                if digest_name and digest_name.split('.')[-1].lower() in ('sha1','sha256','sha512'):
                    params['digest'] = digest_name.split('.')[-1].lower()
                count = _literal(argument(3, 'iterations'), resolve_literal, expected=int)
                if type(count) is int:
                    params['iterations'] = count
            elif name.startswith('argon2.'):
                for index, keyword in enumerate(('time_cost', 'memory_cost', 'parallelism')):
                    value = _literal(argument(index, keyword), resolve_literal, expected=int) if name.endswith('PasswordHasher') else None
                    if type(value) is int:
                        params[keyword] = value
                variant = argument(6, 'type') if name.endswith('PasswordHasher') else None
                variant_name = canonical(variant) if variant is not None else ''
                if variant_name == 'argon2.Type.ID':
                    params['variant'] = 'argon2id'
            elif name in ('bcrypt.gensalt', 'bcrypt.hashpw'):
                salt_call = node
                if name == 'bcrypt.hashpw':
                    salt_call = bound_expression(argument(1, 'salt'))
                if isinstance(salt_call, ast.Call) and canonical(salt_call.func) == 'bcrypt.gensalt':
                    rounds_node = next((k.value for k in salt_call.keywords if k.arg == 'rounds'),
                                       salt_call.args[0] if salt_call.args else None)
                    rounds = _literal(rounds_node, resolve_literal, expected=int)
                    if type(rounds) is int:
                        params['rounds'] = rounds
            emitted = _emit_call(name, text, node.lineno, node.col_offset+1,
                                 original, rules, params, 'python_ast')
            if any(x in name.lower() for x in ('pbkdf2','bcrypt','argon2','scrypt')):
                for event in emitted:
                    event['snippet'] = name + '([password/salt arguments omitted])'
            for event in emitted:
                event.update(source_scope=scope_name(node), source_call=name)
            events.extend(emitted)
            if not emitted and name.split('.')[0] in crypto_roots and not name.endswith(('urandom', 'token_bytes')):
                diagnostics.append(f'Unsupported crypto-like call at line {node.lineno}; identity or settings unresolved.')
        # A PEM in an actual literal is exposed even inside a docstring.
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(r'-----BEGIN [^-]*PRIVATE KEY-----', node.value):
            events.append(dict(secret=True, line=node.lineno, column=node.col_offset+1,
                               snippet='[REDACTED PRIVATE KEY MATERIAL]', parameters={}, evidence='python_ast'))
    # Comments remain optional inventory references, never active assessments.
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type == tokenize.COMMENT:
                events.extend(_comment_events(token.string, token.start[0], rules))
    except tokenize.TokenError:
        diagnostics.append('Incomplete token stream; comment inventory may be partial.')
    return sorted(events, key=lambda e: (e['line'], e['column'])), sorted(set(diagnostics))


def _comment_events(text, line, rules):
    events = []
    for rule in rules:
        if rule['match_type'].value != 'EXPOSED_SECRET' and re.search(rule['pattern'], text, re.I):
            events.append(dict(rule=rule, line=line, column=1, snippet=text,
                               parameters={}, comment=True, evidence='comment'))
    return events


# Strings/comments are tokens, so their delimiters never hide neighboring calls.
_JS_TOKEN = re.compile(r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|(?P<id>[A-Za-z_$][\w$]*)|(?P<number>\d+)|(?P<punct>[^\s])')

def javascript_events(content, rules):
    tokens = list(_JS_TOKEN.finditer(content))
    events, aliases, diagnostics = [], {}, []
    initializations = set()
    for t in tokens:
        if t.lastgroup == 'comment':
            events.extend(_comment_events(t.group(), content.count('\n',0,t.start())+1, rules))
        elif t.lastgroup == 'string' and re.search(r'-----BEGIN [^-]*PRIVATE KEY-----', t.group()):
            events.append(dict(secret=True, line=content.count('\n',0,t.start())+1,column=1,
                               snippet='[REDACTED PRIVATE KEY MATERIAL]', parameters={}, evidence='javascript_lexical'))
        if t.lastgroup == 'string' and t.group().startswith('`') and '${' in t.group():
            diagnostics.append('Template interpolation is not analyzed; review embedded expressions.')
    active = [t for t in tokens if t.lastgroup != 'comment']
    block_depth, depth_at = 0, {}
    for index, token in enumerate(active):
        depth_at[index] = block_depth
        if token.group() == '{': block_depth += 1
        elif token.group() == '}': block_depth = max(0, block_depth-1)
    # A bare require call is the only accepted use of the CommonJS binding.
    # Any declaration, parameter, destructuring or assignment of that name
    # invalidates require provenance throughout this lexical analysis.
    require_shadowed = any(
        token.lastgroup == 'id' and token.group() == 'require'
        and not (index and active[index-1].group() == '.')
        and (index+1 >= len(active) or active[index+1].group() != '('
             or (index and active[index-1].group() in ('function', 'class')))
        for index, token in enumerate(active))
    invalid_bindings, declaration_tokens = set(), set()
    # Only genuine import declarations and require calls are considered bindings.
    for i,t in enumerate(active):
        if t.group() not in ('import','require') or t.lastgroup != 'id':
            continue
        if i and active[i-1].group() == '.':
            continue
        if t.group() == 'require':
            if i+3 >= len(active) or active[i+1].group() != '(' or active[i+2].lastgroup != 'string' or active[i+3].group() != ')':
                continue
            end, module = i+3, active[i+2].group()[1:-1]
        else:
            # Stop at the actual module specifier, including when a semicolon
            # is omitted; neighboring calls are never part of import evidence.
            end, module = None, None
            for index in range(i+1, min(i+60, len(active))):
                if active[index].group() == ';':
                    break
                if active[index].lastgroup == 'string' and (index == i+1 or active[index-1].group() == 'from'):
                    end, module = index, active[index].group()[1:-1]
                    break
            if end is None:
                continue
        span = content[t.start():active[end].end()]
        for rule in rules:
            if rule['match_type'].value=='IMPORT_STATEMENT' and re.search(rule['pattern'],span,re.I):
                events.append(dict(rule=rule,line=content.count('\n',0,t.start())+1,column=1,snippet=span,parameters={},evidence='javascript_lexical'))
        if module in ('crypto', 'node:crypto'):
            # import {createHash as hash} ... / const {createHash: hash}=require(...)
            before = content[max(0,t.start()-250):t.start()] if t.group()=='require' else span
            m = re.search(r'\{([^{}]+)\}\s*=\s*$', before) if t.group() == 'require' else re.search(r'\{([^{}]+)\}', before)
            if m:
                for item in m.group(1).split(','):
                    pair = re.split(r'\s+as\s+|\s*:\s*',item.strip())
                    if pair and all(re.fullmatch(r'\w+', value) for value in pair):
                        alias = pair[-1]
                        if alias in aliases:
                            invalid_bindings.add(alias)
                        aliases[alias]='crypto.'+pair[0]
                        offset = max(0, t.start()-250) if t.group() == 'require' else t.start()
                        declaration_tokens.update(index for index, token in enumerate(active)
                            if token.group() == alias and offset+m.start() <= token.start() < offset+m.end())
                        if depth_at[i] > 0 or (t.group() == 'require' and require_shadowed):
                            invalid_bindings.add(alias)
            else:
                m = (re.search(r'(\w+)\s*=\s*$',before) if t.group()=='require'
                     else re.search(r'import\s+(?:\*\s+as\s+)?(\w+)\s+from',span))
                if m:
                    alias = m.group(1)
                    if alias in aliases:
                        invalid_bindings.add(alias)
                    aliases[alias]='crypto'
                    if depth_at[i] > 0 or (t.group() == 'require' and require_shadowed):
                        invalid_bindings.add(alias)
                    if t.group() == 'require' and i >= 2 and active[i-1].group() == '=' and active[i-2].group() == m.group(1):
                        initializations.add(i-2)

    # Multiple writes, argument bindings and block-local import bindings cannot
    # establish a single namespace. Invalidate the entire file conservatively.
    invalid = set(invalid_bindings)
    if invalid_bindings:
        diagnostics.append('Conditional, repeated or shadowed crypto import binding is unresolved.')
    for root in set(aliases) | {'crypto', 'bcrypt', 'bcryptjs', 'argon2'}:
        writes = 0
        for index, token in enumerate(active):
            if token.lastgroup != 'id' or token.group() != root:
                continue
            previous = active[index-1].group() if index else ''
            after = ''.join(t.group() for t in active[index+1:index+4])
            if index not in declaration_tokens and previous in ('{', '[', ',', ':') and index+1 < len(active) and active[index+1].group() in ('}', ']', ',', ':', '='):
                invalid.add(root)
            if previous == '.':
                if index >= 3 and all(active[n].group() == '.' for n in range(index-3, index)):
                    invalid.add(root)
                continue
            if after.startswith('=>'):
                invalid.add(root)
            # A mutation of a namespace member also invalidates its imported
            # provenance. Do not continue calling a replaced .createHash MD5.
            member_end = index+1
            while member_end < len(active):
                if member_end+1 < len(active) and active[member_end].group() == '.' and active[member_end+1].lastgroup == 'id':
                    member_end += 2
                elif active[member_end].group() == '[':
                    closing = next((n for n in range(member_end+1, len(active)) if active[n].group() == ']'), None)
                    if closing is None: break
                    member_end = closing+1
                else:
                    break
            member_after = ''.join(t.group() for t in active[member_end:member_end+3])
            if member_end > index+1 and ((member_after.startswith('=') and not member_after.startswith(('==','=>')))
                    or re.match(r'^(?:\+\+|--|[+*/%&|^-]=)', member_after)):
                invalid.add(root)
            if after.startswith('=') and not after.startswith(('==', '=>')):
                writes += 1
                if depth_at[index] > 0:
                    invalid.add(root)
            elif re.match(r'^(?:\+\+|--|[+*/%&|^-]=)', after):
                invalid.add(root)
            # A same-named parameter or destructured binding is ambiguous here.
            elif previous in ('(', ',') and after.startswith((',', ')', ':')):
                invalid.add(root)
        initialization = sum(active[index].group() == root for index in initializations)
        if writes > initialization:
            invalid.add(root)

    # Lexical function/class paths are best-effort; closures and dynamic scopes
    # are never modeled as runtime facts.
    scope_at, stack, pending = {}, [], None
    for index, token in enumerate(active):
        value = token.group()
        scope_at[index] = '.'.join(x for x in stack if x) or '<module>'
        if value in ('function', 'class') and index+1 < len(active) and active[index+1].lastgroup == 'id':
            pending = active[index+1].group()
        elif value == '{':
            stack.append(pending)
            pending = None
        elif value == '}' and stack:
            stack.pop()

    for i,t in enumerate(active):
        if t.lastgroup!='id' or (i and active[i-1].group()=='.'):
            continue
        j=i+1
        parts = [t.group()]
        dynamic = False
        while j < len(active):
            if j+1 < len(active) and active[j].group()=='?' and active[j+1].group()=='.':
                j += 2
                if j < len(active) and active[j].group() == '(':
                    break
                if j < len(active) and active[j].lastgroup == 'id':
                    parts.append(active[j].group()); j += 1
                    continue
            if j+1 < len(active) and active[j].group()=='.' and active[j+1].lastgroup=='id':
                parts.append(active[j+1].group()); j += 2
            elif active[j].group()=='[':
                if j+2 < len(active) and active[j+1].lastgroup=='string' and active[j+2].group()==']' and re.fullmatch(r'[\'"][A-Za-z_$][\w$]*[\'"]',active[j+1].group()):
                    parts.append(active[j+1].group()[1:-1]); j += 3
                else:
                    dynamic = True
                    break
            else:
                break
        if dynamic:
            if parts[0] in aliases or parts[0] in ('crypto','bcrypt','argon2','subtle'):
                diagnostics.append('Dynamic computed crypto call target is unresolved; file coverage is partial.')
            continue
        if j>=len(active) or active[j].group()!='(':
            continue
        level=0; end=None
        for k in range(j,len(active)):
            if active[k].lastgroup=='string': continue
            if active[k].group()=='(': level+=1
            if active[k].group()==')':
                level-=1
                if level==0: end=k;break
        if end is None:
            diagnostics.append('Unbalanced call arguments; file coverage is partial.')
            continue
        root,*tail=parts
        if root in invalid:
            diagnostics.append('Reassigned or shadowed crypto alias call is unresolved; no confident identity inferred.')
            continue
        name='.'.join([aliases.get(root,root),*tail])
        # Ignore quoted examples: only the callee token can start this call.
        argtext=' '.join(x.group() for x in active[j:end+1])
        text=name+argtext
        original=content[t.start():active[end].end()]
        params = _parameters(text)
        if any(x in name.lower() for x in ('pbkdf2','bcrypt','argon2','scrypt')):
            params = {}
        # JS arguments are lexical evidence; only numeric and digest literals
        # in known positions/options are extracted. No evaluation or defaults.
        args, current, depth = [], [], 0
        for token in active[j+1:end]:
            value = token.group()
            if value == ',' and depth == 0:
                args.append(''.join(current)); current = []
                continue
            if token.lastgroup != 'string':
                if value in ('(', '[', '{'): depth += 1
                if value in (')', ']', '}'): depth -= 1
            current.append(value)
        args.append(''.join(current))
        if name in ('crypto.pbkdf2','crypto.pbkdf2Sync'):
            if len(args) > 2 and re.fullmatch(r'\d{1,18}', args[2]):
                params['iterations'] = int(args[2])
            if len(args) > 4 and re.fullmatch(r"['\"]sha(?:1|256|512)['\"]",args[4], re.I):
                params['digest'] = args[4][1:-1].lower()
        if name.startswith(('bcrypt.', 'bcryptjs.')):
            index = 0 if 'salt' in name.lower() else 1
            if len(args) > index and re.fullmatch(r'\d{1,2}', args[index]):
                params['rounds'] = int(args[index])
        emitted = _emit_call(name,text,content.count('\n',0,t.start())+1,
                            t.start()-content.rfind('\n',0,t.start()),original,
                            rules,params,'javascript_lexical')
        for event in emitted:
            event.update(source_scope=scope_at[i], source_call=name)
            if any(x in name.lower() for x in ('pbkdf2','bcrypt','argon2','scrypt')):
                event['snippet'] = name + '([password/salt arguments omitted])'
        events.extend(emitted)
        if not emitted and name.split('.')[0] in ('crypto','bcrypt','bcryptjs','argon2','subtle'):
            diagnostics.append('Unsupported crypto-like lexical call; identity or settings unresolved.')
    return events, sorted(set(diagnostics))
