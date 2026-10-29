"""Bounded password-cost assessment; never infer defaults or inspect secrets.

Policy: OWASP Password Storage Cheat Sheet, reviewed 2026-10-30.
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
An adequate explicit cost is a scoped observation, not a password-storage audit.
"""
POLICY_SOURCE = 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'
SAFE_PARAMETERS = {'key_bits', 'curve', 'mode', 'iterations', 'digest', 'rounds',
                   'memory_cost', 'time_cost', 'parallelism', 'variant'}


def safe_parameters(parameters):
    """Whitelist non-secret scalar settings, even across adapter boundaries."""
    if not isinstance(parameters, dict):
        return {}
    return {k: v for k, v in parameters.items() if k in SAFE_PARAMETERS
            and ((type(v) is int and abs(v) <= 2**63-1)
                 or (isinstance(v, str) and len(v) <= 64))}


def assess_kdf(algorithm, parameters):
    """Return None for non-KDFs, else adequate/weak/unknown plus reasons."""
    low = algorithm.lower()
    family = next((x for x in ('pbkdf2', 'argon2', 'bcrypt', 'scrypt') if x in low), None)
    if not family:
        return None
    p = safe_parameters(parameters)
    reasons, weak = [], []

    def positive(name):
        value = p.get(name)
        if type(value) is not int:
            reasons.append(name + ' is missing or dynamic')
            return None
        if value <= 0:
            weak.append(name + ' must be positive')
            return None
        return value

    if family == 'pbkdf2':
        minimum = {'sha256': 600000, 'sha512': 220000, 'sha1': 1400000}.get(p.get('digest'))
        if minimum is None:
            reasons.append('digest is missing, dynamic or unsupported by the cost policy')
        count = positive('iterations')
        if count is not None and minimum is not None and count < minimum:
            weak.append('iterations are below the digest-specific OWASP minimum')
    elif family == 'bcrypt':
        rounds = positive('rounds')
        if rounds is not None and not 10 <= rounds <= 31:
            weak.append('bcrypt rounds must be between 10 and 31')
    elif family == 'argon2':
        memory, passes, parallel = (positive(k) for k in ('memory_cost', 'time_cost', 'parallelism'))
        if p.get('variant') != 'argon2id':
            reasons.append('Argon2 variant is missing or unsupported; defaults are not inferred')
        if memory is not None and parallel is not None and memory < 8 * parallel:
            weak.append('Argon2 memory is below its per-lane minimum')
        if memory is not None and passes is not None and p.get('variant') == 'argon2id':
            if not any(memory >= m and passes >= t for m, t in
                       ((47104, 1), (19456, 2), (12288, 3), (9216, 4), (7168, 5))):
                weak.append('Argon2id memory/time cost is below the OWASP tradeoff profiles')
    else:
        reasons.append('scrypt parameter policy is not implemented; review settings')
    return dict(status='weak' if weak else 'unknown' if reasons else 'adequate',
                assessment_scope='explicit_cost_only', salt_status='unknown',
                reasons=weak + reasons,
                unknown_reasons=reasons + ['Salt generation, uniqueness and runtime handling are not assessed by the static cost policy'],
                policy_source=POLICY_SOURCE)
