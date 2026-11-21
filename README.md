# SocialGuard Pro
Case management and complaint drafting for genuine impersonation, harassment, fraud and copyright cases on Facebook, Instagram and TikTok.

## Run
    npm install
    JWT_SECRET="$(openssl rand -hex 32)" npm start
Deploy behind HTTPS (set NODE_ENV=production). Back up data.db and uploads/.

## What needs official access
- Submitting reports: Meta and TikTok offer no public abuse-report API. The app opens the official form; you submit.
- Copyright: use each platform's own copyright form (links built in). Verify links, since platforms move them.
- Case status: platforms provide no status API, so outcomes are recorded by you with the platform notice.
- Profile data collection: not implemented. Scraping violates platform terms; paste evidence yourself.

## Safeguards
Truthfulness attestation, 5 new cases/day, one case per profile, no auto-submit, no bulk import, outcomes need pasted proof.
