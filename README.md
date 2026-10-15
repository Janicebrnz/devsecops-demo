# DevSecOps Demo: Self-Healing OWASP Security Gate (Jenkins + GitHub)

Pipeline: Checkout -> SAST (AST-based OWASP scan) -> Auto-Remediate -> Re-Scan Gate
-> Security Regression Tests -> Push fix branch -> Deploy

Needs only Python 3.9+ and Git on the Jenkins agent. No pip installs.

## One-time setup
1. Create a GitHub repo (e.g. `devsecops-demo`) and push this folder to `main`.
2. Edit `GH_REPO` in the Jenkinsfile to `github.com/<you>/devsecops-demo.git`.
3. GitHub -> Settings -> Developer settings -> Personal access tokens -> create a token with `repo` scope.
4. Jenkins -> Manage Jenkins -> Credentials -> add "Username with password":
   username = GitHub username, password = the token, ID = `github-creds`.
5. Jenkins -> New Item -> Pipeline -> "Pipeline script from SCM" -> Git -> repo URL, branch `*/main`, script path `Jenkinsfile`.
6. Trigger: tick "Poll SCM" with `H/2 * * * *` (works on localhost with no extras).
   Or use a GitHub webhook (`http://<jenkins>/github-webhook/`) if Jenkins is publicly reachable.
7. On Windows agents replace `sh` with `bat` and `python3` with `python`.

## Demo
1. Push as-is (vulnerable) -> scan finds 10 issues -> auto-fix -> tests pass -> build YELLOW (UNSTABLE).
   Open Build -> Artifacts: reports/before/report.html, reports/after/report.html, reports/fixes.patch.
   A `security-autofix` branch appears on GitHub with the fixed code.
2. Block scenario: append to app.py
       def ping(host):
           import os
           os.system("ping -c 1 " + host)
   Push -> this one has no safe automatic fix -> Re-Scan Gate fails -> build RED, deploy blocked.
3. Merge `security-autofix` into main (clean code) -> build GREEN.

## Run locally
    python3 -m unittest discover -s tests      # 4 security tests fail on vulnerable code
    python3 security/owasp_scan.py             # scan
    python3 security/owasp_scan.py --fix       # remediate
