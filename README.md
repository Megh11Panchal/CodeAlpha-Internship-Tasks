# Task 3: Secure Coding Review

**Intern:** [Your Name]
**Company task:** CodeAlpha, Task 3 (Secure Coding Review)

## What is in this folder

| File | Description |
|---|---|
| `Secure_Coding_Review_Report.docx` | Main report: findings, risk, vulnerable code, fixes, and test results |
| `code/original_app.py` | Sample Flask app I wrote for the audit. It contains intentional security flaws. |
| `code/fixed_app.py` | Corrected version of the same app, with all findings fixed except rate limiting |
| `code/scan.py` | Small Python scanner I used to find issues automatically |

## About the code

The sample app was written by me for this audit, because no specific project was provided. It is for learning only and must not be deployed.

## How to run

1. Install Flask: `pip install flask pyyaml`
2. Run the original app: `python code/original_app.py`
3. Run the scanner: `python code/scan.py code/original_app.py`

## Summary of results

The review found 15 issues (2 Critical, 7 High, 3 Medium, 3 Low). All were fixed in `fixed_app.py` except F-15 (rate limiting on login), which is listed as a recommendation.
