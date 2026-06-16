#!/usr/bin/env python3
"""One vulnerable -> fixed example per CWE, in the language that best shows it.

These supplement the multi-ecosystem, hand-curated entries in cwe_data.py:
they cover additional KEV CWEs with a single representative example in the
most relevant popular language (Java, Node.js or Python; C for the
memory-safety classes). generate.py merges these in, so every covered CWE
gets a vulnerable/fixed pair even when it isn't in the curated Top-25 set.

Format: CWE number -> {"eco": language, "bad": ..., "good": ...}
'eco' must match a highlighter name used elsewhere (Node.js/Python/Java/Go/
PHP/C/C++).
"""

def _e(eco, bad, good):
    return {"eco": eco, "bad": bad.strip("\n"), "good": good.strip("\n")}


EXAMPLES_SINGLE = {
 # --- memory safety (C) ------------------------------------------------
 119: _e("C", r"""
char buf[64];
strcpy(buf, input);          /* no bounds check -> out-of-bounds write */
""", r"""
char buf[64];
snprintf(buf, sizeof(buf), "%s", input);   /* bounded copy */
"""),
 190: _e("C", r"""
int len = a + b;             /* may overflow and wrap negative/small */
char *p = malloc(len);       /* under-allocates */
memcpy(p, src, a + b);       /* heap overflow */
""", r"""
if (b > 0 && a > SIZE_MAX - b) return -1;  /* detect wrap first */
size_t len = (size_t)a + b;
char *p = malloc(len);
"""),
 191: _e("C", r"""
size_t n = recv_len - header_len;   /* underflows if recv_len < header_len */
memcpy(dst, src, n);                /* huge copy */
""", r"""
if (recv_len < header_len) return -1;
size_t n = recv_len - header_len;
memcpy(dst, src, n);
"""),
 415: _e("C", r"""
free(p);
/* ... */
free(p);                     /* double free */
""", r"""
free(p);
p = NULL;                    /* free(NULL) is a no-op */
/* ... */
free(p);
"""),
 401: _e("C", r"""
char *p = malloc(n);
if (!validate(p)) return -1; /* leaks p */
""", r"""
char *p = malloc(n);
if (!validate(p)) { free(p); return -1; }
free(p);
"""),
 369: _e("C", r"""
int r = total / count;       /* count may be 0 -> crash */
""", r"""
if (count == 0) return -1;
int r = total / count;
"""),
 134: _e("C", r"""
printf(user_input);          /* format-string injection */
""", r"""
printf("%s", user_input);
"""),

 # --- authn / session / crypto ----------------------------------------
 287: _e("Node.js", r"""
// trusts a client-supplied identity header
if (req.headers['x-user']) { req.user = req.headers['x-user']; next(); }
""", r"""
const token = (req.headers.authorization || '').split(' ')[1];
try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
catch { res.sendStatus(401); }
"""),
 295: _e("Python", r"""
import requests
requests.get(url, verify=False)     # disables TLS certificate validation
""", r"""
import requests
requests.get(url)                   # verify=True by default; validates chain
"""),
 312: _e("Python", r"""
db.save(user_id, password)          # password stored in cleartext
""", r"""
import bcrypt
db.save(user_id, bcrypt.hashpw(password.encode(), bcrypt.gensalt()))
"""),
 319: _e("Python", r"""
requests.post("http://api.example.com/login", data=creds)  # plaintext HTTP
""", r"""
requests.post("https://api.example.com/login", data=creds) # TLS
"""),
 327: _e("Java", r"""
Cipher c = Cipher.getInstance("DES");                 // broken cipher
""", r"""
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");   // authenticated, modern
"""),
 328: _e("Python", r"""
import hashlib
digest = hashlib.md5(password.encode()).hexdigest()   # fast + broken for pw
""", r"""
import bcrypt
digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
"""),
 330: _e("Python", r"""
import random
token = "%030x" % random.randrange(16**30)   # predictable PRNG
""", r"""
import secrets
token = secrets.token_hex(16)                # CSPRNG
"""),
 384: _e("Node.js", r"""
// keeps the same session id across the login boundary
req.session.user = user;
""", r"""
req.session.regenerate(err => {     // fresh id on privilege change
  req.session.user = user;
});
"""),
 613: _e("Node.js", r"""
req.session.cookie.maxAge = null;   // session never expires
""", r"""
req.session.cookie.maxAge = 30 * 60 * 1000;   // 30-minute idle timeout
"""),
 614: _e("Node.js", r"""
res.cookie('sid', id);              // no security flags
""", r"""
res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'strict' });
"""),
 798: _e("Python", r"""
API_KEY = "sk_live_51H8abc..."      # secret committed in source
""", r"""
import os
API_KEY = os.environ["API_KEY"]     # from environment / secret manager
"""),

 # --- injection / parsing ---------------------------------------------
 611: _e("Java", r"""
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.newDocumentBuilder().parse(input);   // external entities enabled -> XXE
""", r"""
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.newDocumentBuilder().parse(input);
"""),
 643: _e("Python", r"""
expr = "//user[name='" + name + "']"   # XPath injection
tree.xpath(expr)
""", r"""
expr = "//user[name=$n]"
tree.xpath(expr, n=name)               # parameterized
"""),
 90: _e("Python", r"""
flt = "(uid=" + username + ")"         # LDAP injection
conn.search(base, flt)
""", r"""
from ldap3.utils.conv import escape_filter_chars
conn.search(base, "(uid=%s)" % escape_filter_chars(username))
"""),
 95: _e("Python", r"""
result = eval(user_expr)               # arbitrary code execution
""", r"""
import ast
result = ast.literal_eval(user_expr)   # data literals only
"""),
 88: _e("Python", r"""
subprocess.run(f"git log {ref}", shell=True)   # argument/flag injection
""", r"""
subprocess.run(["git", "log", "--", ref])       # -- ends option parsing
"""),
 113: _e("Java", r"""
resp.setHeader("Location", req.getParameter("next"));  // CR/LF injectable
""", r"""
String next = req.getParameter("next");
if (next.matches("[\\w/-]+")) resp.setHeader("Location", next);
"""),
 117: _e("Java", r"""
log.info("login: " + username);        // newlines forge log entries
""", r"""
log.info("login: {}", username.replaceAll("[\\r\\n]", "_"));
"""),
 1236: _e("Python", r"""
writer.writerow([name, value])         # =cmd() executes when opened in Excel
""", r"""
def neutralize(s):
    return "'" + str(s) if str(s)[:1] in "=+-@" else s
writer.writerow([neutralize(name), neutralize(value)])
"""),
 1321: _e("Node.js", r"""
function merge(t, s){ for (const k in s) t[k] = s[k]; return t; }  // __proto__
""", r"""
function merge(t, s){
  for (const k in s) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    t[k] = s[k];
  }
  return t;
}
"""),
 1333: _e("Node.js", r"""
const re = /^(a+)+$/;          // catastrophic backtracking (ReDoS)
re.test(userInput);
""", r"""
const re = /^a+$/;             // linear; bound input length too
re.test(userInput.slice(0, 1000));
"""),
 400: _e("Node.js", r"""
app.post('/upload', (req, res) => { /* no body-size limit -> DoS */ });
""", r"""
app.use(express.json({ limit: '100kb' }));   // cap request size
"""),

 # --- files / paths / permissions / privacy ---------------------------
 367: _e("Python", r"""
if os.access(path, os.W_OK):       # check
    open(path, "w").write(data)    # ...use: race window (TOCTOU)
""", r"""
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:      # atomic; no check/use gap
    f.write(data)
"""),
 59: _e("Python", r"""
open(path, "w").write(data)        # follows an attacker-planted symlink
""", r"""
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_EXCL, 0o600)
os.write(fd, data)
"""),
 426: _e("Python", r"""
subprocess.run("convert in.png out.png", shell=True)  # PATH-dependent binary
""", r"""
subprocess.run(["/usr/bin/convert", "in.png", "out.png"])  # absolute, no shell
"""),
 732: _e("Python", r"""
os.chmod(secret, 0o777)            # world-readable/writable
""", r"""
os.chmod(secret, 0o600)            # owner only
"""),
 209: _e("Python", r"""
except Exception as e:
    return str(e), 500             # leaks stack/internal details to client
""", r"""
except Exception:
    app.logger.exception("request failed")   # detail stays server-side
    return "Internal error", 500
"""),
 601: _e("Node.js", r"""
app.get('/go', (req, res) => res.redirect(req.query.url));   // open redirect
""", r"""
const allow = new Set(['/home', '/help']);
app.get('/go', (req, res) =>
  res.redirect(allow.has(req.query.url) ? req.query.url : '/home'));
"""),
}
