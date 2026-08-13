# Deploy to Cloudflare Pages — free static configuration

The supplied package intentionally uses **no Pages Functions, Workers, KV, D1, R2 or paid API**. It is ordinary static HTML/CSS/JavaScript.

## Option A — dashboard upload

1. Unzip the package.
2. Sign in to Cloudflare.
3. Go to **Workers & Pages**.
4. Create a **Pages** project using Direct Upload.
5. Upload the contents of the package root (the folder containing `index.html`).
6. Deploy.

No build command is required. No environment variables are required.

## Option B — connect a Git repository

Push the package contents to a repository and connect it to Cloudflare Pages.

Recommended settings:

- Framework preset: `None`
- Build command: leave empty
- Build output directory: `/` (repository root) or the folder containing `index.html`
- Environment variables: none

## Project name

Suggested: `sovereignroot`, producing `sovereignroot.pages.dev` **if Cloudflare confirms that project name is available**.

If you use another hostname, update these files before public launch:

- `robots.txt`
- `sitemap.xml`
- `protocol/sovereignty.schema.json` (`$id`)

## Why this stays free

The project does not invoke Pages Functions. All application work — questionnaire logic, key generation, encryption, signing and verification — runs in the visitor's browser.

## Security headers

Cloudflare Pages automatically reads the included `_headers` file. Do not remove the Content Security Policy without understanding the security impact.
