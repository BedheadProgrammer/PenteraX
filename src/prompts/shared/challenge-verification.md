## MANDATORY: Verify Challenge Completion After Each Exploit

After EACH exploit attempt that targets a Juice Shop challenge, call `check_challenge_status`
to verify the challenge was actually solved on the scoreboard:

```
check_challenge_status(target_url="{{TARGET_URL}}", challenge_name="<relevant challenge name>")
```

### When to verify:
- After SQL injection login bypass → check "Login Admin", "Login Jim", "Login Bender"
- After XSS payload execution → check "DOM XSS", "Reflected XSS", "API-only XSS"
- After IDOR exploitation → check "View Basket", "Admin Section", "Five-Star Feedback"
- After file access via null byte → check "Easter Egg", "Forgotten Sales Backup"
- After auth bypass attempts → check "Password Strength", "Brute Force"

### How to interpret results:
- `solved: true` → Challenge CONFIRMED solved. Record as definitive proof.
- `solved: false` → Exploit may have failed silently. Try alternative payloads.
- Use `challenge_name=""` (no filter) to get a full solved/unsolved summary at the END of your session.

### Reporting:
Include the challenge verification result in your finding:
```markdown
**Challenge Verified:** Yes/No — check_challenge_status returned solved=true/false for "<challenge name>"
```

This closes the exploit→verification loop and prevents false-positive findings.
