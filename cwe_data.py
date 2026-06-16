#!/usr/bin/env python3
"""Single source of truth for the CWE reference (man pages + HTML + PDF).

Each entry carries a description and mitigation that are language-independent,
plus one vulnerable -> fixed code example PER ECOSYSTEM. Defensive material:
every "bad" snippet is a pattern to recognise and avoid, paired with the fix.
"""

DATE = "2025-12-11"
SOURCE = "CWE Top 25 (2025)"
MANUAL = "Software Weakness Reference"

# Example helper: ex(eco, bad, good). 'eco' is also used to pick a highlighter.
def ex(eco, bad, good):
    return {"eco": eco, "bad": bad, "good": good}

ENTRIES = []

ENTRIES += [
{
 "id":"CWE-79","rank":1,"prev":"1",
 "name":"Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
 "category":"Injection / Web",
 "desc":[
  "User-controllable input is embedded in a web page served to other users "
  "without being neutralised as executable script. In the victim's browser the "
  "attacker's markup or JavaScript runs in the site's security context, enabling "
  "session theft, credential capture and account takeover.",
  "Forms: stored (payload persisted server-side), reflected (echoed from the "
  "request) and DOM-based (written into the DOM client-side).",
 ],
 "fix_text":
 "Contextually encode untrusted data on output (HTML, attribute, JS contexts). "
 "Prefer an auto-escaping template engine, set a strict Content-Security-Policy, "
 "and never build HTML by raw string concatenation.",
 "see":["CWE-80","CWE-116","OWASP A03:2021 Injection"],
 "examples":[
  ex("Node.js", r"""
app.get('/hi', (req, res) =>
  res.send('<h1>Hello ' + req.query.name + '</h1>'));   // reflected XSS
""", r"""
const escapeHtml = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
app.get('/hi', (req, res) =>
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>'));
// Better: an auto-escaping template (e.g. <%= name %> in EJS).
"""),
  ex("Python", r"""
@app.get('/hi')
def hi():
    return '<h1>Hello ' + request.args['name'] + '</h1>'   # reflected XSS
""", r"""
@app.get('/hi')
def hi():
    # Jinja auto-escapes by default
    return render_template_string('<h1>Hello {{ name }}</h1>',
                                  name=request.args['name'])
"""),
  ex("Java", r"""
String name = req.getParameter("name");
resp.getWriter().println("<h1>Hello " + name + "</h1>");   // reflected XSS
""", r"""
import org.owasp.encoder.Encode;
String name = req.getParameter("name");
resp.getWriter().println("<h1>Hello " + Encode.forHtml(name) + "</h1>");
"""),
  ex("Go", r"""
name := r.URL.Query().Get("name")
fmt.Fprintf(w, "<h1>Hello %s</h1>", name)   // reflected XSS
""", r"""
import "html/template"
var t = template.Must(template.New("p").Parse("<h1>Hello {{.}}</h1>"))
// html/template context-encodes automatically
t.Execute(w, r.URL.Query().Get("name"))
"""),
  ex("PHP", r"""
echo "<h1>Hello " . $_GET['name'] . "</h1>";   // reflected XSS
""", r"""
echo "<h1>Hello "
   . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')
   . "</h1>";
"""),
 ],
},
{
 "id":"CWE-89","rank":2,"prev":"3",
 "name":"Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
 "category":"Injection",
 "desc":[
  "User input is concatenated into an SQL statement, so attacker-supplied "
  "metacharacters change the query's meaning. This allows reading or modifying "
  "arbitrary data, authentication bypass, and sometimes command execution on the "
  "database host.",
 ],
 "fix_text":
 "Use parameterized queries / prepared statements so the driver sends SQL "
 "structure and values separately. Apply least-privilege DB accounts and "
 "allow-list any identifier (table/column) that cannot be parameterized.",
 "see":["CWE-20","CWE-943","OWASP A03:2021 Injection"],
 "examples":[
  ex("Node.js", r"""
// node-postgres
const r = await db.query(
  "SELECT * FROM users WHERE name = '" + name + "'");   // injectable
""", r"""
const r = await db.query(
  "SELECT * FROM users WHERE name = $1", [name]);       // bound parameter
"""),
  ex("Python", r"""
q = "SELECT * FROM users WHERE name = '%s'" % username   # injectable
conn.execute(q).fetchall()
""", r"""
q = "SELECT * FROM users WHERE name = ?"                  # placeholder
conn.execute(q, (username,)).fetchall()
"""),
  ex("Java", r"""
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery(
  "SELECT * FROM users WHERE name = '" + name + "'");    // injectable
""", r"""
PreparedStatement ps = conn.prepareStatement(
  "SELECT * FROM users WHERE name = ?");
ps.setString(1, name);                                   // bound parameter
ResultSet rs = ps.executeQuery();
"""),
  ex("Go", r"""
rows, _ := db.Query(
  "SELECT * FROM users WHERE name = '" + name + "'")     // injectable
""", r"""
rows, _ := db.Query(
  "SELECT * FROM users WHERE name = ?", name)            // bound parameter
"""),
  ex("PHP", r"""
// PDO
$rows = $db->query(
  "SELECT * FROM users WHERE name = '" . $name . "'");   // injectable
""", r"""
$stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$name]);                                 // bound parameter
$rows = $stmt->fetchAll();
"""),
 ],
},
{
 "id":"CWE-352","rank":3,"prev":"4",
 "name":"Cross-Site Request Forgery (CSRF)",
 "category":"Web / Session",
 "desc":[
  "A state-changing request is accepted without proof the user intended it. "
  "Because browsers attach cookies automatically, a malicious page can make a "
  "logged-in victim's browser submit a forged request the server cannot "
  "distinguish from a legitimate one.",
 ],
 "fix_text":
 "Require an unpredictable per-session anti-CSRF token on every state-changing "
 "request and reject it if missing/wrong. Set session cookies SameSite=Lax or "
 "Strict, and re-authenticate for the most sensitive actions.",
 "see":["CWE-1275","CWE-306","OWASP A01:2021 Broken Access Control"],
 "examples":[
  ex("Node.js", r"""
app.post('/transfer', (req, res) => {        // trusts the session cookie only
  transfer(req.session.user, req.body.to, req.body.amount);
  res.send('ok');
});
""", r"""
app.post('/transfer', (req, res) => {
  if (!req.body.csrf || req.body.csrf !== req.session.csrf)
    return res.sendStatus(403);              // anti-CSRF token required
  transfer(req.session.user, req.body.to, req.body.amount);
  res.send('ok');
});
// session cookie: { sameSite: 'lax' }
"""),
  ex("Python", r"""
@app.post('/transfer')
def transfer():                              # no token check
    do_transfer(session['user'], request.form['to'], request.form['amount'])
    return 'ok'
""", r"""
@app.post('/transfer')
def transfer():
    if not hmac.compare_digest(session.get('csrf',''), request.form.get('csrf','')):
        abort(403)                           # anti-CSRF token required
    do_transfer(session['user'], request.form['to'], request.form['amount'])
    return 'ok'
# app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
"""),
  ex("Java", r"""
// Spring Security
http.csrf(csrf -> csrf.disable());           // protection switched off
""", r"""
// Spring Security enables CSRF tokens by default; keep it on
http.csrf(Customizer.withDefaults());
// and use SameSite cookies: server.servlet.session.cookie.same-site=lax
"""),
  ex("Go", r"""
http.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
    doTransfer(user(r), r.FormValue("to"), r.FormValue("amount"))   // no token
})
""", r"""
import "github.com/gorilla/csrf"
// Wrap the mux; the middleware validates a per-session token on unsafe methods
mux := csrf.Protect(key, csrf.SameSite(csrf.SameSiteLaxMode))(router)
// templates embed {{ .csrfField }} which the middleware checks
"""),
  ex("PHP", r"""
// transfer.php
do_transfer($_SESSION['user'], $_POST['to'], $_POST['amount']);   // no token
""", r"""
if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
    http_response_code(403); exit;           // anti-CSRF token required
}
do_transfer($_SESSION['user'], $_POST['to'], $_POST['amount']);
// session_set_cookie_params(['samesite' => 'Lax']);
"""),
 ],
},
{
 "id":"CWE-862","rank":4,"prev":"9",
 "name":"Missing Authorization",
 "category":"Access Control",
 "desc":[
  "No authorization check is performed when an actor accesses a resource or "
  "performs an action. Authentication establishes who the user is, but the code "
  "never confirms they are allowed to do the operation, so any authenticated (or "
  "anonymous) user reaches privileged functionality.",
 ],
 "fix_text":
 "Enforce an explicit authorization decision on every sensitive operation, "
 "ideally centrally (middleware/filter/annotation) so it cannot be forgotten. "
 "Deny by default; check the specific permission for the specific action.",
 "see":["CWE-285","CWE-863","OWASP A01:2021 Broken Access Control"],
 "examples":[
  ex("Node.js", r"""
app.delete('/users/:id', (req, res) => {     // no role check
  users.delete(req.params.id);
  res.sendStatus(204);
});
""", r"""
const requireAdmin = (req, res, next) =>
  req.user?.role === 'admin' ? next() : res.sendStatus(403);
app.delete('/users/:id', requireAdmin, (req, res) => {
  users.delete(req.params.id);
  res.sendStatus(204);
});
"""),
  ex("Python", r"""
@app.delete('/users/<int:uid>')
def delete_user(uid):                        # no role check
    User.delete(uid)
    return '', 204
""", r"""
@app.delete('/users/<int:uid>')
@require_role('admin')                        # explicit authorization
def delete_user(uid):
    User.delete(uid)
    return '', 204
"""),
  ex("Java", r"""
@DeleteMapping("/users/{id}")
public void delete(@PathVariable Long id) {   // no role check
    userService.delete(id);
}
""", r"""
@PreAuthorize("hasRole('ADMIN')")             // checked before the method runs
@DeleteMapping("/users/{id}")
public void delete(@PathVariable Long id) {
    userService.delete(id);
}
"""),
  ex("Go", r"""
func deleteUser(w http.ResponseWriter, r *http.Request) {   // no role check
    users.Delete(mux.Vars(r)["id"])
    w.WriteHeader(204)
}
""", r"""
func deleteUser(w http.ResponseWriter, r *http.Request) {
    if !currentUser(r).IsAdmin {
        http.Error(w, "forbidden", http.StatusForbidden); return
    }
    users.Delete(mux.Vars(r)["id"])
    w.WriteHeader(204)
}
"""),
  ex("PHP", r"""
// delete_user.php
delete_user($_GET['id']);                     // no role check
""", r"""
if (($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403); exit;            // explicit authorization
}
delete_user($_GET['id']);
"""),
 ],
},
{
 "id":"CWE-787","rank":5,"prev":"2",
 "name":"Out-of-bounds Write",
 "category":"Memory Safety",
 "desc":[
  "Data is written past the end (or before the start) of an intended buffer, "
  "corrupting adjacent memory: other variables, heap metadata, return addresses "
  "or function pointers. Leads to crashes, data corruption or code execution. "
  "Managed runtimes (Java, Go, Python, Node) bounds-check and largely prevent "
  "this class; the examples are therefore in C and C++.",
 ],
 "fix_text":
 "Bound every write by the destination size (snprintf, memcpy with a validated "
 "length). In C++ prefer std::string / std::vector. Enable FORTIFY_SOURCE, stack "
 "canaries and AddressSanitizer; consider Rust for new components.",
 "see":["CWE-120","CWE-121","CWE-122","CWE-125"],
 "examples":[
  ex("C", r"""
void copy_name(const char *src) {
    char buf[16];
    strcpy(buf, src);        /* no limit: overflows if src > 15 chars */
}
""", r"""
void copy_name(const char *src) {
    char buf[16];
    snprintf(buf, sizeof buf, "%s", src);   /* truncates, never overflows */
}
"""),
  ex("C++", r"""
char buf[16];
std::strcpy(buf, src.c_str());   // same unbounded write as C
""", r"""
std::string buf = src;           // manages its own storage; cannot overflow
"""),
 ],
},
{
 "id":"CWE-22","rank":6,"prev":"5",
 "name":"Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
 "category":"Injection / File System",
 "desc":[
  "User input builds a file path without neutralising sequences such as \"../\" "
  "that resolve outside the intended directory, letting an attacker read or write "
  "files anywhere the process can reach.",
 ],
 "fix_text":
 "Resolve to a canonical absolute path and verify it remains within the intended "
 "base directory before opening. Prefer allow-listing known file identifiers "
 "over accepting raw paths.",
 "see":["CWE-23","CWE-36","OWASP A01:2021 Broken Access Control"],
 "examples":[
  ex("Node.js", r"""
fs.readFile('/var/www/docs/' + req.query.name, cb);   // ../../etc/passwd
""", r"""
const base = '/var/www/docs';
const full = path.resolve(base, req.query.name);
if (!full.startsWith(base + path.sep)) return res.sendStatus(400);
fs.readFile(full, cb);
"""),
  ex("Python", r"""
with open('/var/www/docs/' + name) as f:   # ../../etc/passwd
    return f.read()
""", r"""
import os
BASE = '/var/www/docs'
full = os.path.realpath(os.path.join(BASE, name))
if os.path.commonpath([full, BASE]) != BASE:
    raise ValueError('path traversal blocked')
with open(full) as f:
    return f.read()
"""),
  ex("Java", r"""
new FileInputStream("/var/www/docs/" + name);   // ../../etc/passwd
""", r"""
Path base = Paths.get("/var/www/docs").toRealPath();
Path full = base.resolve(name).normalize();
if (!full.startsWith(base)) throw new SecurityException("traversal");
Files.readAllBytes(full);
"""),
  ex("Go", r"""
os.ReadFile("/var/www/docs/" + name)   // ../../etc/passwd
""", r"""
base := "/var/www/docs"
full := filepath.Join(base, name)
if !strings.HasPrefix(filepath.Clean(full), base+string(os.PathSeparator)) {
    http.Error(w, "bad path", 400); return
}
os.ReadFile(full)
"""),
  ex("PHP", r"""
readfile('/var/www/docs/' . $_GET['name']);   // ../../etc/passwd
""", r"""
$base = '/var/www/docs';
$full = realpath($base . '/' . $_GET['name']);
if ($full === false || strncmp($full, $base . '/', strlen($base) + 1) !== 0) {
    http_response_code(400); exit;
}
readfile($full);
"""),
 ],
},
{
 "id":"CWE-416","rank":7,"prev":"8",
 "name":"Use After Free",
 "category":"Memory Safety",
 "desc":[
  "Memory is referenced after being freed. The freed block may be reallocated for "
  "another purpose, so the dangling pointer aliases unrelated data; results range "
  "from crashes to information disclosure to attacker-controlled execution. A "
  "C/C++ manual-memory weakness.",
 ],
 "fix_text":
 "Null out pointers after free, establish clear ownership, and avoid multiple "
 "aliases to freed memory. Use AddressSanitizer/Valgrind; in C++ use smart "
 "pointers; consider Rust where its ownership model prevents the class.",
 "see":["CWE-415","CWE-825","CWE-672"],
 "examples":[
  ex("C", r"""
char *p = malloc(32);
free(p);
strcpy(p, "late");   /* dangling: use-after-free (and a later double free) */
""", r"""
char *p = malloc(32);
if (!p) return;
/* ... use p ... */
free(p);
p = NULL;            /* dangling pointer can no longer be dereferenced */
"""),
  ex("C++", r"""
int *p = new int(42);
delete p;
std::cout << *p;     // use-after-free
""", r"""
auto p = std::make_unique<int>(42);   // ownership clear; freed at scope end
std::cout << *p;
"""),
 ],
},
{
 "id":"CWE-125","rank":8,"prev":"6",
 "name":"Out-of-bounds Read",
 "category":"Memory Safety",
 "desc":[
  "Data is read past the end (or before the start) of a buffer, leaking adjacent "
  "memory (keys, pointers, other data) or crashing. Often arises from trusting a "
  "length or index from untrusted input. A C/C++ class; managed runtimes "
  "bounds-check.",
 ],
 "fix_text":
 "Validate every index and length against the actual buffer size before reading; "
 "use correct loop bounds. In C++ prefer .at() and range-based iteration. "
 "Sanitizers and fuzzing find many of these.",
 "see":["CWE-126","CWE-127","CWE-20"],
 "examples":[
  ex("C", r"""
int sum_n(const int *a, size_t len, size_t n) {
    int s = 0;
    for (size_t i = 0; i <= n; i++)   /* '<=' and unchecked n read past end */
        s += a[i];
    return s;
}
""", r"""
int sum_n(const int *a, size_t len, size_t n) {
    int s = 0;
    size_t limit = (n < len) ? n : len;   /* clamp to the buffer */
    for (size_t i = 0; i < limit; i++)
        s += a[i];
    return s;
}
"""),
  ex("C++", r"""
int v = vec[i];     // operator[] does no bounds check; i may be out of range
""", r"""
int v = vec.at(i);  // bounds-checked: throws std::out_of_range instead
"""),
 ],
},
]

ENTRIES += [
{
 "id":"CWE-78","rank":9,"prev":"7",
 "name":"Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
 "category":"Injection",
 "desc":[
  "Untrusted input is placed into a command run by a system shell without "
  "neutralising shell metacharacters (; | & $ ` etc.), letting an attacker append "
  "or alter commands and gain code execution with the app's privileges.",
 ],
 "fix_text":
 "Avoid invoking a shell. Pass arguments as a vector to an exec-style API so the "
 "OS treats them as data, not shell syntax. If a shell is unavoidable, strictly "
 "allow-list input. Run with least privilege.",
 "see":["CWE-77","CWE-88","OWASP A03:2021 Injection"],
 "examples":[
  ex("Node.js", r"""
const { exec } = require('child_process');
exec('ping -c1 ' + host);   // exec spawns a shell -> injectable
""", r"""
const { execFile } = require('child_process');
execFile('ping', ['-c1', host]);   // argument vector, no shell
"""),
  ex("Python", r"""
os.system('ping -c1 ' + host)   # shell -> injectable
""", r"""
import subprocess
subprocess.run(['ping', '-c1', host], check=True)   # argument vector, no shell
"""),
  ex("Java", r"""
Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c1 " + host});
""", r"""
new ProcessBuilder("ping", "-c1", host).start();   // no shell
"""),
  ex("Go", r"""
exec.Command("sh", "-c", "ping -c1 "+host).Run()   // shell -> injectable
""", r"""
exec.Command("ping", "-c1", host).Run()            // argument vector, no shell
"""),
  ex("PHP", r"""
system('ping -c1 ' . $host);   // shell -> injectable
""", r"""
system('ping -c1 ' . escapeshellarg($host));   // argument quoted
"""),
 ],
},
{
 "id":"CWE-94","rank":10,"prev":"11",
 "name":"Improper Control of Generation of Code (Code Injection)",
 "category":"Injection",
 "desc":[
  "The application builds code from untrusted input and then interprets/executes "
  "it, so the payload runs in the application's own language runtime - usually "
  "full control of the process. Typical sinks are eval() and dynamic templates.",
 ],
 "fix_text":
 "Never pass untrusted data to eval/exec or a general script engine. Use a "
 "purpose-built safe parser for the intended data (a math-expression library, a "
 "literal parser, or a data format like JSON). Keep code and data separate.",
 "see":["CWE-95","CWE-502","OWASP A03:2021 Injection"],
 "examples":[
  ex("Node.js", r"""
const result = eval(req.body.expr);   // arbitrary code execution
""", r"""
const { evaluate } = require('mathjs');
const result = evaluate(req.body.expr);   // restricted math grammar, no JS eval
"""),
  ex("Python", r"""
return eval(expr)   # e.g. expr="__import__('os').system('id')"
""", r"""
import ast, operator
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}
def ev(n):
    if isinstance(n, ast.Constant): return n.value
    if isinstance(n, ast.BinOp):    return _OPS[type(n.op)](ev(n.left), ev(n.right))
    raise ValueError('unsupported')
return ev(ast.parse(expr, mode='eval').body)
"""),
  ex("Java", r"""
// Nashorn / any javax.script engine
engine.eval(userInput);   // arbitrary code execution
""", r"""
// Do NOT feed untrusted input to a script engine.
// Parse the intended grammar with a typed, restricted parser instead:
double result = new net.objecthunter.exp4j.ExpressionBuilder(userInput)
                    .build().evaluate();   // arithmetic only
"""),
  ex("PHP", r"""
eval('$r = ' . $_GET['expr'] . ';');   // arbitrary code execution
""", r"""
// Never eval() user input. Use a dedicated math evaluator:
$r = (new \NXP\MathExecutor())->execute($_GET['expr']);   // arithmetic only
"""),
 ],
},
{
 "id":"CWE-120","rank":11,"prev":"NEW",
 "name":"Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
 "category":"Memory Safety",
 "desc":[
  "Data is copied into a fixed-size buffer without verifying it fits; the excess "
  "overwrites adjacent memory. The classic root of decades of remote code "
  "execution. A C/C++ class.",
 ],
 "fix_text":
 "Use size-bounded copies (snprintf, strlcpy, memcpy with a validated length) and "
 "always pass the destination capacity. In C++ prefer std::string. Enable "
 "compiler hardening and fuzz parsers.",
 "see":["CWE-121","CWE-122","CWE-787"],
 "examples":[
  ex("C", r"""
char msg[32];
sprintf(msg, "Welcome, %s!", user);   /* overflows if user is long */
""", r"""
char msg[32];
snprintf(msg, sizeof msg, "Welcome, %s!", user);   /* bounded */
"""),
  ex("C++", r"""
char msg[32];
std::sprintf(msg, "Welcome, %s!", user.c_str());   // unbounded
""", r"""
std::string msg = "Welcome, " + user + "!";        // grows as needed
"""),
 ],
},
{
 "id":"CWE-434","rank":12,"prev":"10",
 "name":"Unrestricted Upload of File with Dangerous Type",
 "category":"Web / File Handling",
 "desc":[
  "Uploads are accepted without adequately restricting the type or how the file "
  "is handled. An attacker uploads executable content (e.g. a web shell) into a "
  "location the server executes, achieving remote code execution.",
 ],
 "fix_text":
 "Validate by content (not just extension); allow-list permitted types; generate "
 "a server-side random filename; store uploads outside the web root or where "
 "scripts never execute; serve with a safe Content-Type/Content-Disposition.",
 "see":["CWE-94","CWE-79","OWASP A04:2021 Insecure Design"],
 "examples":[
  ex("Node.js", r"""
// multer with original name under the web root
const dest = '/var/www/html/uploads/' + req.file.originalname;   // shell.js
fs.renameSync(req.file.path, dest);
""", r"""
import { fileTypeFromFile } from 'file-type';
const ALLOW = { 'image/png': 'png', 'image/jpeg': 'jpg' };
const t = await fileTypeFromFile(req.file.path);
if (!t || !ALLOW[t.mime]) return res.sendStatus(415);
const name = crypto.randomUUID() + '.' + ALLOW[t.mime];
fs.renameSync(req.file.path, '/srv/uploads/' + name);   // outside web root
"""),
  ex("Python", r"""
# Flask
file.save(os.path.join('/var/www/html/uploads', file.filename))   # shell.py
""", r"""
import imghdr, uuid
kind = imghdr.what(file.stream)            # validate by content
if kind not in ('png', 'jpeg'):
    abort(415)
name = f"{uuid.uuid4()}.{kind}"
file.save(os.path.join('/srv/uploads', name))   # outside web root
"""),
  ex("Java", r"""
// Spring
file.transferTo(new File("/var/www/html/" + file.getOriginalFilename()));
""", r"""
String mime = new Tika().detect(file.getInputStream());   // validate content
Map<String,String> allow = Map.of("image/png","png","image/jpeg","jpg");
if (!allow.containsKey(mime)) throw new ResponseStatusException(UNSUPPORTED_MEDIA_TYPE);
String name = UUID.randomUUID() + "." + allow.get(mime);
file.transferTo(Path.of("/srv/uploads", name));   // outside web root
"""),
  ex("Go", r"""
dst, _ := os.Create("/var/www/html/uploads/" + header.Filename)   // shell
io.Copy(dst, file)
""", r"""
buf := make([]byte, 512)
n, _ := file.Read(buf)
mime := http.DetectContentType(buf[:n])   // validate by content
ext, ok := map[string]string{"image/png": "png", "image/jpeg": "jpg"}[mime]
if !ok { http.Error(w, "type", 415); return }
file.Seek(0, io.SeekStart)
dst, _ := os.Create("/srv/uploads/" + uuid.NewString() + "." + ext)  // outside root
io.Copy(dst, file)
"""),
  ex("PHP", r"""
$dest = '/var/www/html/uploads/' . $_FILES['f']['name'];   // shell.php
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
""", r"""
$allow = ['image/png' => 'png', 'image/jpeg' => 'jpg'];
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['f']['tmp_name']);
if (!isset($allow[$mime])) { http_response_code(415); exit; }
$name = bin2hex(random_bytes(16)) . '.' . $allow[$mime];
move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/' . $name); // outside root
"""),
 ],
},
{
 "id":"CWE-476","rank":13,"prev":"21",
 "name":"NULL Pointer Dereference",
 "category":"Memory Safety / Reliability",
 "desc":[
  "A pointer expected to be valid is NULL when dereferenced, usually crashing the "
  "program (denial of service). Typically from an unchecked return value or "
  "unhandled error path. Shown in C/C++; the managed analog is an unchecked null "
  "object reference.",
 ],
 "fix_text":
 "Check the result of anything that can return NULL before dereferencing, and "
 "define the failure path. Static analysers catch many; in modern C++/Rust use "
 "optional types to make absence explicit.",
 "see":["CWE-690","CWE-252"],
 "examples":[
  ex("C", r"""
struct cfg *c = find_config(key);   /* may return NULL */
printf("%d\n", c->timeout);          /* crash if c == NULL */
""", r"""
struct cfg *c = find_config(key);
if (c == NULL) { log_warn("missing %s", key); return; }
printf("%d\n", c->timeout);
"""),
  ex("C++", r"""
Cfg *c = find_config(key);   // may return nullptr
std::cout << c->timeout;      // crash if null
""", r"""
if (std::optional<Cfg> c = find_config(key))   // explicit presence check
    std::cout << c->timeout;
else
    log_warn("missing config");
"""),
 ],
},
{
 "id":"CWE-121","rank":14,"prev":"NEW",
 "name":"Stack-based Buffer Overflow",
 "category":"Memory Safety",
 "desc":[
  "An overflow of a buffer on the call stack. Because local buffers sit near saved "
  "registers and the return address, an overflow can redirect execution - "
  "historically the most exploited overflow. A C/C++ class.",
 ],
 "fix_text":
 "Never use unbounded input functions (gets). Read into a sized buffer, enable "
 "stack canaries, ASLR and non-executable stacks, and fuzz parsers. In C++ use "
 "std::string / std::getline.",
 "see":["CWE-120","CWE-122","CWE-787"],
 "examples":[
  ex("C", r"""
char line[64];
gets(line);          /* unbounded read straight onto the stack */
""", r"""
char line[64];
if (fgets(line, sizeof line, stdin))   /* bounded by sizeof line */
    process(line);
"""),
  ex("C++", r"""
char line[64];
std::cin >> line;    // operator>> into char[] can overflow the stack buffer
""", r"""
std::string line;
std::getline(std::cin, line);   // grows to fit the input
"""),
 ],
},
{
 "id":"CWE-502","rank":15,"prev":"16",
 "name":"Deserialization of Untrusted Data",
 "category":"Injection / Data Handling",
 "desc":[
  "Untrusted data is deserialized without sufficient verification. Rich formats "
  "can reconstruct arbitrary object graphs and trigger callbacks during "
  "construction, so a crafted payload ('gadget chain') can lead to remote code "
  "execution, denial of service or logic tampering.",
 ],
 "fix_text":
 "Do not deserialize untrusted data with formats that can execute code (pickle, "
 "Java native serialization, PHP unserialize, node-serialize). Use a data-only "
 "format such as JSON, validate against a schema, and if unavoidable restrict "
 "allowed types and sign the payload.",
 "see":["CWE-94","CWE-915","OWASP A08:2021 Integrity Failures"],
 "examples":[
  ex("Node.js", r"""
const obj = require('node-serialize').unserialize(data);   // can execute code
""", r"""
const obj = JSON.parse(data);   // data only; no code execution
// ... then validate the expected shape ...
"""),
  ex("Python", r"""
return pickle.loads(blob)   # can instantiate arbitrary objects / run code
""", r"""
data = json.loads(blob)     # data only; no code execution
# ... validate expected fields ...
return data
"""),
  ex("Java", r"""
Object o = new ObjectInputStream(in).readObject();   // gadget-chain RCE
""", r"""
// Prefer JSON with an explicit target type:
Foo o = new ObjectMapper().readValue(in, Foo.class);
// If native serialization is unavoidable, allow-list classes:
// ois.setObjectInputFilter(f -> f.serialClass()==Foo.class ? ALLOWED : REJECTED);
"""),
  ex("PHP", r"""
$o = unserialize($_COOKIE['data']);   // object injection
""", r"""
$o = json_decode($_COOKIE['data'], true);   // data only
// If unserialize is required, forbid objects:
// $o = unserialize($data, ['allowed_classes' => false]);
"""),
 ],
},
{
 "id":"CWE-122","rank":16,"prev":"NEW",
 "name":"Heap-based Buffer Overflow",
 "category":"Memory Safety",
 "desc":[
  "An overflow of a heap-allocated buffer. Overrunning it corrupts adjacent heap "
  "objects or allocator metadata; with heap grooming this becomes a reliable code "
  "execution primitive. Common in parsers. A C/C++ class.",
 ],
 "fix_text":
 "Allocate based on the actual required size and bound every copy by it. Validate "
 "length fields and use checked arithmetic for size calculations to avoid integer "
 "overflow. In C++ prefer std::vector. Test with AddressSanitizer.",
 "see":["CWE-120","CWE-787","CWE-190"],
 "examples":[
  ex("C", r"""
char *buf = malloc(8);
memcpy(buf, input, input_len);   /* input_len unchecked: heap overflow */
""", r"""
if (input_len > 8) return -1;    /* reject oversize input */
char *buf = malloc(8);
if (!buf) return -1;
memcpy(buf, input, input_len);   /* within bounds */
"""),
  ex("C++", r"""
int *a = new int[8];
std::memcpy(a, src, n * sizeof(int));   // n unchecked: heap overflow
""", r"""
std::vector<int> a(src, src + n);       // allocates exactly n; no overflow
"""),
 ],
},
]

ENTRIES += [
{
 "id":"CWE-863","rank":17,"prev":"18",
 "name":"Incorrect Authorization",
 "category":"Access Control",
 "desc":[
  "An authorization check exists but is logically flawed, so it permits actions it "
  "should deny: comparing the wrong field, only checking authentication, or "
  "failing open. Unlike Missing Authorization, the check is present but wrong.",
 ],
 "fix_text":
 "Check the specific permission for the specific object the actor touches, not "
 "merely that they are authenticated. Fail closed on any error. Centralise the "
 "policy so the same correct check is reused.",
 "see":["CWE-862","CWE-285","CWE-639"],
 "examples":[
  ex("Node.js", r"""
app.get('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);   // any logged-in user can read any order
});
""", r"""
app.get('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.userId !== req.user.id) return res.sendStatus(403);
  res.json(order);   // object-level ownership check
});
"""),
  ex("Python", r"""
@app.get('/orders/<int:oid>')
def view(oid):
    order = Order.get(oid)
    if current_user.is_authenticated:   # only checks login, not ownership
        return order.json()
    abort(401)
""", r"""
@app.get('/orders/<int:oid>')
def view(oid):
    order = Order.get(oid)
    if order is None or order.owner_id != current_user.id:
        abort(403)                      # object-level ownership check
    return order.json()
"""),
  ex("Java", r"""
@GetMapping("/orders/{id}")
public Order view(@PathVariable Long id, Authentication auth) {
    if (auth.isAuthenticated())         // login only, not ownership
        return repo.findById(id).orElseThrow();
    throw new AccessDeniedException("401");
}
""", r"""
@GetMapping("/orders/{id}")
public Order view(@PathVariable Long id, @AuthenticationPrincipal User me) {
    Order o = repo.findById(id).orElseThrow();
    if (!o.getOwnerId().equals(me.getId()))
        throw new AccessDeniedException("403");   // ownership check
    return o;
}
"""),
  ex("Go", r"""
func view(w http.ResponseWriter, r *http.Request) {
    o := getOrder(id(r))
    if loggedIn(r) {            // login only
        json.NewEncoder(w).Encode(o)
    }
}
""", r"""
func view(w http.ResponseWriter, r *http.Request) {
    o := getOrder(id(r))
    if o == nil || o.OwnerID != currentUser(r).ID {
        http.Error(w, "forbidden", 403); return   // ownership check
    }
    json.NewEncoder(w).Encode(o)
}
"""),
  ex("PHP", r"""
$order = get_order($_GET['id']);
if (isset($_SESSION['user'])) {        // login only
    echo json_encode($order);
}
""", r"""
$order = get_order($_GET['id']);
if (!$order || $order['owner_id'] !== ($_SESSION['user']['id'] ?? null)) {
    http_response_code(403); exit;     // ownership check
}
echo json_encode($order);
"""),
 ],
},
{
 "id":"CWE-20","rank":18,"prev":"12",
 "name":"Improper Input Validation",
 "category":"Validation",
 "desc":[
  "Input is received but not validated (or wrongly validated) for the properties "
  "needed for safe processing. A broad root cause feeding many other weaknesses; "
  "malformed, out-of-range or wrong-type data reaches sensitive logic.",
 ],
 "fix_text":
 "Validate every input on the server against an explicit spec: type, range, "
 "length, format and allowed set (allow-list, not deny-list). Reject invalid "
 "input rather than sanitising it. Schema validators make this systematic.",
 "see":["CWE-79","CWE-89","CWE-1284"],
 "examples":[
  ex("Node.js", r"""
const total = req.body.qty * PRICE;   // qty could be negative, huge, NaN
charge(req.user, total);
""", r"""
const qty = Number(req.body.qty);
if (!Number.isInteger(qty) || qty < 1 || qty > 100)
  return res.status(400).json({ error: 'invalid qty' });
charge(req.user, qty * PRICE);
"""),
  ex("Python", r"""
total = int(request.form['qty']) * PRICE   # no range check; may raise/negative
charge(user, total)
""", r"""
try:
    qty = int(request.form['qty'])
except ValueError:
    abort(400)
if not 1 <= qty <= 100:
    abort(400)
charge(user, qty * PRICE)
"""),
  ex("Java", r"""
int qty = Integer.parseInt(req.getParameter("qty"));   // no range check
charge(user, qty * PRICE);
""", r"""
// Bean Validation on the request DTO:
public record OrderReq(@Min(1) @Max(100) int qty) {}
@PostMapping("/order")
public void order(@Valid @RequestBody OrderReq req) {   // rejected if invalid
    charge(user, req.qty() * PRICE);
}
"""),
  ex("Go", r"""
qty, _ := strconv.Atoi(r.FormValue("qty"))   // error ignored, no range check
charge(user, qty*PRICE)
""", r"""
qty, err := strconv.Atoi(r.FormValue("qty"))
if err != nil || qty < 1 || qty > 100 {
    http.Error(w, "invalid qty", 400); return
}
charge(user, qty*PRICE)
"""),
  ex("PHP", r"""
$total = (int)$_POST['qty'] * PRICE;   // (int) cast hides bad input
charge($user, $total);
""", r"""
$qty = filter_input(INPUT_POST, 'qty', FILTER_VALIDATE_INT,
                    ['options' => ['min_range' => 1, 'max_range' => 100]]);
if ($qty === false || $qty === null) { http_response_code(400); exit; }
charge($user, $qty * PRICE);
"""),
 ],
},
{
 "id":"CWE-284","rank":19,"prev":"NEW",
 "name":"Improper Access Control",
 "category":"Access Control",
 "desc":[
  "Access to a resource is not restricted, or is incorrectly restricted, from an "
  "unauthorized actor. The broad parent of missing/incorrect authorization, weak "
  "permission models, and unprotected resources.",
 ],
 "fix_text":
 "Enforce access control at the server for every resource and entry point, "
 "default to deny, and rely on a centralised, well-tested authorization layer "
 "rather than UI restrictions or obscurity. Apply least privilege.",
 "see":["CWE-862","CWE-863","OWASP A01:2021 Broken Access Control"],
 "examples":[
  ex("Node.js", r"""
// /reports route is only linked from the admin UI, but nothing guards it
app.get('/reports/:name', (req, res) =>
  res.sendFile('/reports/' + req.params.name));   // reachable by anyone
""", r"""
app.get('/reports/:name', requireAuth, (req, res) => {
  if (!canRead(req.user, req.params.name)) return res.sendStatus(403);
  res.sendFile(safePath('/reports', req.params.name));
});
"""),
  ex("Python", r"""
@app.get('/reports/<name>')
def report(name):                       # no guard; relies on UI not linking it
    return send_from_directory('/reports', name)
""", r"""
@app.get('/reports/<name>')
@login_required
def report(name):
    if not can_read(current_user, name):
        abort(403)
    return send_from_directory('/reports', name)
"""),
  ex("Java", r"""
protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    serveFile("/reports/" + req.getParameter("name"), resp);   // unguarded
}
""", r"""
protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    if (!authz.canRead(currentUser(req), req.getParameter("name"))) {
        resp.sendError(403); return;
    }
    serveFile(safePath(req.getParameter("name")), resp);
}
"""),
  ex("Go", r"""
http.HandleFunc("/reports/", func(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "/reports/"+r.URL.Query().Get("name"))   // unguarded
})
""", r"""
http.HandleFunc("/reports/", func(w http.ResponseWriter, r *http.Request) {
    if !canRead(currentUser(r), r.URL.Query().Get("name")) {
        http.Error(w, "forbidden", 403); return
    }
    http.ServeFile(w, r, safePath("/reports", r.URL.Query().Get("name")))
})
"""),
  ex("PHP", r"""
// report.php - no guard
readfile('/reports/' . basename($_GET['name']));
""", r"""
if (!can_read($_SESSION['user'] ?? null, $_GET['name'])) {
    http_response_code(403); exit;
}
readfile('/reports/' . basename($_GET['name']));
"""),
 ],
},
{
 "id":"CWE-200","rank":20,"prev":"17",
 "name":"Exposure of Sensitive Information to an Unauthorized Actor",
 "category":"Information Disclosure",
 "desc":[
  "Sensitive information (credentials, keys, personal data, internal details) is "
  "disclosed to an actor not authorized to see it - directly (returning secret "
  "fields) or indirectly (verbose errors, debug output, metadata).",
 ],
 "fix_text":
 "Return only the fields each caller is entitled to (allow-list). Keep secrets "
 "out of logs and error messages, disable debug output in production, and return "
 "generic errors to clients while logging detail server-side.",
 "see":["CWE-209","CWE-532","OWASP A02:2021 Cryptographic Failures"],
 "examples":[
  ex("Node.js", r"""
const user = await User.findById(req.params.id);
res.json(user);   // serialises passwordHash, totpSecret, ...
""", r"""
const user = await User.findById(req.params.id);
res.json({ id: user.id, name: user.name });   // explicit safe fields
"""),
  ex("Python", r"""
u = User.get(uid)
return jsonify(u.__dict__)   # includes password hash, secrets
""", r"""
u = User.get(uid)
return jsonify({'id': u.id, 'name': u.name})   # safe fields only
"""),
  ex("Java", r"""
@GetMapping("/users/{id}")
public User get(@PathVariable Long id) {        // entity leaks all columns
    return repo.findById(id).orElseThrow();
}
""", r"""
public record UserDto(Long id, String name) {}
@GetMapping("/users/{id}")
public UserDto get(@PathVariable Long id) {     // DTO with safe fields only
    User u = repo.findById(id).orElseThrow();
    return new UserDto(u.getId(), u.getName());
}
"""),
  ex("Go", r"""
json.NewEncoder(w).Encode(user)   // struct exports PasswordHash, etc.
""", r"""
// Tag secret fields so they never serialise:
type User struct {
    ID           int    `json:"id"`
    Name         string `json:"name"`
    PasswordHash string `json:"-"`   // excluded from JSON
}
json.NewEncoder(w).Encode(user)
"""),
  ex("PHP", r"""
echo json_encode($user);   // whole row incl. password_hash
""", r"""
echo json_encode(['id' => $user['id'], 'name' => $user['name']]);  // safe fields
"""),
 ],
},
{
 "id":"CWE-306","rank":21,"prev":"25",
 "name":"Missing Authentication for Critical Function",
 "category":"Authentication",
 "desc":[
  "A critical function is reachable without authentication: admin panels, debug "
  "interfaces, firmware-update or internal APIs are exposed so any actor who can "
  "reach the network path can invoke them.",
 ],
 "fix_text":
 "Require authentication for every sensitive function and verify it server-side; "
 "do not rely on an endpoint being hidden. Combine with authorization and an "
 "extra factor for the most dangerous operations.",
 "see":["CWE-862","CWE-287","OWASP A07:2021 Auth Failures"],
 "examples":[
  ex("Node.js", r"""
app.post('/admin/shutdown', (req, res) => {   // no auth
  systemShutdown();
  res.send('bye');
});
""", r"""
app.post('/admin/shutdown', requireAuth, requireRole('admin'), (req, res) => {
  systemShutdown();
  res.send('bye');
});
"""),
  ex("Python", r"""
@app.post('/admin/shutdown')   # no auth
def shutdown():
    system_shutdown()
    return 'bye'
""", r"""
@app.post('/admin/shutdown')
@login_required
@require_role('admin')
def shutdown():
    system_shutdown()
    return 'bye'
"""),
  ex("Java", r"""
// Spring Security
http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").permitAll());
""", r"""
http.authorizeHttpRequests(a -> a
    .requestMatchers("/admin/**").hasRole("ADMIN")   // authenticated + authorized
    .anyRequest().authenticated());
"""),
  ex("Go", r"""
http.HandleFunc("/admin/shutdown", func(w http.ResponseWriter, r *http.Request) {
    systemShutdown()   // no auth
})
""", r"""
http.Handle("/admin/shutdown", requireRole("admin",
  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      systemShutdown()
  })))
"""),
  ex("PHP", r"""
// admin_shutdown.php - no auth
system_shutdown();
""", r"""
if (empty($_SESSION['user']) || ($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(401); exit;
}
system_shutdown();
"""),
 ],
},
{
 "id":"CWE-918","rank":22,"prev":"19",
 "name":"Server-Side Request Forgery (SSRF)",
 "category":"Web / Injection",
 "desc":[
  "The server fetches a URL supplied or influenced by the user without validating "
  "the destination, so an attacker coerces requests to internal services, "
  "link-local cloud metadata endpoints, or arbitrary hosts - bypassing network "
  "controls and exposing internal data.",
 ],
 "fix_text":
 "Allow-list permitted hosts/schemes; resolve the hostname and reject private, "
 "loopback and link-local ranges; disable redirects to disallowed targets; and "
 "isolate outbound requests from internal/metadata services.",
 "see":["CWE-20","CWE-610","OWASP A10:2021 SSRF"],
 "examples":[
  ex("Node.js", r"""
const r = await fetch(req.query.url);   // http://169.254.169.254/... reachable
""", r"""
const ALLOWED = new Set(['api.partner.example']);
const u = new URL(req.query.url);
if (!ALLOWED.has(u.hostname)) return res.sendStatus(400);
const { address } = await dns.promises.lookup(u.hostname);
if (isPrivateIp(address)) return res.sendStatus(400);
const r = await fetch(u, { redirect: 'manual' });
"""),
  ex("Python", r"""
return requests.get(url).text   # url may target internal/metadata services
""", r"""
import ipaddress, socket
ALLOWED = {'api.partner.example'}
host = requests.utils.urlparse(url).hostname
if host not in ALLOWED: raise ValueError('host not allowed')
ip = ipaddress.ip_address(socket.gethostbyname(host))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    raise ValueError('internal address blocked')
return requests.get(url, allow_redirects=False, timeout=5).text
"""),
  ex("Java", r"""
InputStream in = new URL(url).openStream();   // internal targets reachable
""", r"""
URI u = URI.create(url);
if (!Set.of("api.partner.example").contains(u.getHost()))
    throw new SecurityException("host not allowed");
InetAddress ip = InetAddress.getByName(u.getHost());
if (ip.isSiteLocalAddress() || ip.isLoopbackAddress() || ip.isLinkLocalAddress())
    throw new SecurityException("internal address blocked");
HttpClient.newBuilder().followRedirects(Redirect.NEVER).build()
          .send(HttpRequest.newBuilder(u).build(), BodyHandlers.ofString());
"""),
  ex("Go", r"""
resp, _ := http.Get(url)   // internal targets reachable
""", r"""
u, _ := neturl.Parse(url)
if u.Hostname() != "api.partner.example" {
    http.Error(w, "host not allowed", 400); return
}
ips, _ := net.LookupIP(u.Hostname())
for _, ip := range ips {
    if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
        http.Error(w, "internal blocked", 400); return
    }
}
client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
    return http.ErrUseLastResponse }}
resp, _ := client.Get(u.String())
"""),
  ex("PHP", r"""
echo file_get_contents($_GET['url']);   // internal targets reachable
""", r"""
$host = parse_url($_GET['url'], PHP_URL_HOST);
if ($host !== 'api.partner.example') { http_response_code(400); exit; }
$ip = gethostbyname($host);
if (!filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    http_response_code(400); exit;   // private/reserved blocked
}
$ch = curl_init($_GET['url']);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
echo curl_exec($ch);
"""),
 ],
},
{
 "id":"CWE-77","rank":23,"prev":"13",
 "name":"Improper Neutralization of Special Elements used in a Command (Command Injection)",
 "category":"Injection",
 "desc":[
  "Untrusted input is incorporated into a command (to a shell, interpreter or "
  "other command processor) without neutralising elements that change which "
  "commands run. OS command injection (CWE-78) is the best-known child.",
 ],
 "fix_text":
 "Avoid building commands from untrusted strings; use APIs that take an argument "
 "array, prefer native library calls over shelling out, and allow-list acceptable "
 "values. Run with least privilege.",
 "see":["CWE-78","CWE-88","OWASP A03:2021 Injection"],
 "examples":[
  ex("Node.js", r"""
exec('wc -l ' + file);   // shell -> 'a; rm -rf /' runs extra commands
""", r"""
execFile('wc', ['-l', file]);   // argument vector, no shell
"""),
  ex("Python", r"""
os.popen('wc -l ' + f).read()   # shell -> injectable
""", r"""
subprocess.run(['wc', '-l', f], capture_output=True, check=True)
"""),
  ex("Java", r"""
Runtime.getRuntime().exec(new String[]{"sh", "-c", "wc -l " + file});
""", r"""
new ProcessBuilder("wc", "-l", file).start();   // no shell
"""),
  ex("Go", r"""
exec.Command("sh", "-c", "wc -l "+file).Run()   // shell -> injectable
""", r"""
exec.Command("wc", "-l", file).Run()            // argument vector, no shell
"""),
  ex("PHP", r"""
echo shell_exec('wc -l ' . $_GET['file']);   // shell -> injectable
""", r"""
$file = $_GET['file'];
if (!preg_match('/^[\w.\-]+$/', $file)) { http_response_code(400); exit; }
echo shell_exec('wc -l ' . escapeshellarg($file));
"""),
 ],
},
{
 "id":"CWE-639","rank":24,"prev":"30",
 "name":"Authorization Bypass Through User-Controlled Key (IDOR)",
 "category":"Access Control",
 "desc":[
  "A user-supplied key (e.g. a record ID) looks up a resource without verifying "
  "the user is authorized for that specific object. Changing the identifier (an "
  "'insecure direct object reference') exposes other users' data.",
 ],
 "fix_text":
 "Tie object lookups to the authenticated principal: filter by owner, or verify "
 "ownership after lookup and deny otherwise. Unpredictable identifiers help but "
 "never replace an authorization check.",
 "see":["CWE-862","CWE-863","OWASP A01:2021 Broken Access Control"],
 "examples":[
  ex("Node.js", r"""
const inv = await Invoice.findById(req.params.id);   // any id by URL edit
res.json(inv);
""", r"""
const inv = await Invoice.findOne({ _id: req.params.id, owner: req.user.id });
if (!inv) return res.sendStatus(404);   // scoped to the caller
res.json(inv);
"""),
  ex("Python", r"""
inv = Invoice.get(request.args['id'])   # any id
return inv.json()
""", r"""
inv = Invoice.query.filter_by(id=request.args['id'],
                              owner_id=current_user.id).first_or_404()
return inv.json()
"""),
  ex("Java", r"""
@GetMapping("/invoices/{id}")
public Invoice get(@PathVariable Long id) {           // any id
    return repo.findById(id).orElseThrow();
}
""", r"""
@GetMapping("/invoices/{id}")
public Invoice get(@PathVariable Long id, @AuthenticationPrincipal User me) {
    return repo.findByIdAndOwnerId(id, me.getId())    // scoped to caller
               .orElseThrow(() -> new AccessDeniedException("403"));
}
"""),
  ex("Go", r"""
row := db.QueryRow("SELECT * FROM invoices WHERE id = ?", id(r))   // any id
""", r"""
row := db.QueryRow(
  "SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
  id(r), currentUser(r).ID)   // scoped to caller
"""),
  ex("PHP", r"""
$inv = $db->query("SELECT * FROM invoices WHERE id = " . (int)$_GET['id']);
echo json_encode($inv->fetch());   // any id
""", r"""
$stmt = $db->prepare(
  "SELECT * FROM invoices WHERE id = ? AND owner_id = ?");
$stmt->execute([$_GET['id'], $_SESSION['user']['id']]);   // scoped to caller
echo json_encode($stmt->fetch());
"""),
 ],
},
{
 "id":"CWE-770","rank":25,"prev":"26",
 "name":"Allocation of Resources Without Limits or Throttling",
 "category":"Resource Management / Availability",
 "desc":[
  "A reusable resource (memory, file handles, threads, connections, CPU) is "
  "allocated for an actor without limits or throttling. An attacker triggers "
  "excessive allocation to exhaust the resource and deny service.",
 ],
 "fix_text":
 "Impose explicit limits: maximum request/body size, per-client rate limiting, "
 "quotas, timeouts, and capped pools with back-pressure. Reject work that exceeds "
 "limits early rather than allocating first.",
 "see":["CWE-400","CWE-789","CWE-307"],
 "examples":[
  ex("Node.js", r"""
app.post('/render', (req, res) => {   // no size/rate limit
  let body = '';
  req.on('data', c => body += c);     // unbounded buffering
  req.on('end', () => res.send(heavyRender(body)));
});
""", r"""
app.use(express.text({ limit: '1mb' }));            // body cap
app.post('/render', rateLimit({ max: 10, windowMs: 60000 }), (req, res) => {
  res.send(heavyRender(req.body));
});
"""),
  ex("Python", r"""
@app.post('/render')
def render():
    data = request.get_data()   # no size/rate limit
    return heavy_render(data)
""", r"""
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024   # 1 MiB cap
@app.post('/render')
@limiter.limit('10/minute')                           # per-client throttle
def render():
    return heavy_render(request.get_data())
"""),
  ex("Java", r"""
@PostMapping("/render")
public String render(@RequestBody String body) {   // no size/rate limit
    return heavyRender(body);
}
""", r"""
// application.properties: spring.servlet.multipart.max-request-size=1MB
@PostMapping("/render")
@RateLimiter(name = "render")   // resilience4j per-client throttle
public String render(@RequestBody @Size(max = 1_000_000) String body) {
    return heavyRender(body);
}
"""),
  ex("Go", r"""
func render(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)   // unbounded read
    w.Write(heavyRender(body))
}
""", r"""
func render(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20)   // 1 MiB cap
    body, err := io.ReadAll(r.Body)
    if err != nil { http.Error(w, "too large", 413); return }
    w.Write(heavyRender(body))   // plus a rate-limiting middleware + timeouts
}
"""),
  ex("PHP", r"""
$data = file_get_contents('php://input');   // bounded only by memory_limit
echo heavy_render($data);
""", r"""
// php.ini: post_max_size = 1M ; and rate-limit at the web server / WAF.
$len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($len > 1048576) { http_response_code(413); exit; }
$data = file_get_contents('php://input');
echo heavy_render($data);
"""),
 ],
},
]

# --- Appendix: NOT part of the official Top 25 -----------------------------
ENTRIES += [
{
 "id":"CWE-470","rank":None,"prev":"appendix",
 "name":"Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)",
 "category":"Injection / Appendix (not in Top 25)",
 "desc":[
  "NOTE: CWE-470 is NOT part of the 2025 CWE Top 25; it is included here as a "
  "related weakness for completeness.",
  "Externally-controlled input chooses which class is loaded or which "
  "method/code is invoked via reflection. An attacker who controls the name can "
  "instantiate unexpected classes or reach code paths that enable code execution, "
  "denial of service, or logic bypass. Closely related to CWE-94 and CWE-502.",
 ],
 "fix_text":
 "Never let untrusted input name a class, method, or module directly. Map a small "
 "set of allowed identifiers to known types/handlers with an allow-list, and "
 "reject anything else.",
 "see":["CWE-94","CWE-502","CWE-20"],
 "examples":[
  ex("Java", r"""
String cls = req.getParameter("handler");
Object h = Class.forName(cls).getDeclaredConstructor().newInstance();   // any class
""", r"""
Map<String, Supplier<Handler>> allow = Map.of(
    "csv",  CsvHandler::new,
    "json", JsonHandler::new);
Supplier<Handler> s = allow.get(req.getParameter("handler"));
if (s == null) throw new IllegalArgumentException("unknown handler");
Handler h = s.get();   // only known types can be created
"""),
  ex("C#/.NET", r"""
var t = Type.GetType(Request["handler"]);          // any type
var h = Activator.CreateInstance(t);
""", r"""
IHandler h = Request["handler"] switch {
    "csv"  => new CsvHandler(),
    "json" => new JsonHandler(),
    _      => throw new ArgumentException("unknown handler"),
};   // allow-list of known types
"""),
  ex("Python", r"""
mod = importlib.import_module(request.args['module'])
obj = getattr(mod, request.args['cls'])()   # arbitrary class from user input
""", r"""
HANDLERS = {'csv': CsvHandler, 'json': JsonHandler}
cls = HANDLERS.get(request.args['handler'])
if cls is None:
    abort(400)
obj = cls()   # only known classes
"""),
  ex("Node.js", r"""
const handler = require(req.query.module);   // dynamic require from user input
handler.run();
""", r"""
const HANDLERS = { csv: () => require('./csv'), json: () => require('./json') };
const make = HANDLERS[req.query.handler];
if (!make) return res.sendStatus(400);
make().run();   // allow-listed modules only
"""),
 ],
},
]

# Normalise: strip leading/trailing blank lines from every code snippet.
for _e in ENTRIES:
    for _x in _e["examples"]:
        _x["bad"] = _x["bad"].strip("\n")
        _x["good"] = _x["good"].strip("\n")
