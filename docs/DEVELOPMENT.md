# GitHub Pages development preview

This repository publishes two views through one GitHub Pages deployment:

- Production: <https://stackarmor.github.io/rfc-fedramp-vdr/>
- Development preview: <https://stackarmor.github.io/rfc-fedramp-vdr/dev/>

The workflow always assembles production from the `main` branch and the preview
from the `dev` branch. A push to `dev` can update `/dev/`, but it cannot replace
the production root. A push or merge to `main` updates production.

## One-time repository setup

After `.github/workflows/pages.yml` has been merged into `main`:

1. Open **Settings → Pages**.
2. Under **Build and deployment**, change **Source** from **Deploy from a
   branch** to **GitHub Actions**.
3. Open **Actions → Pages - production and dev preview** and run the workflow
   once.
4. If the `github-pages` environment has a deployment-branch restriction,
   permit both `main` and `dev`. The workflow serializes deployments and always
   packages both branches together.

The current site should remain on `main:/docs` until the workflow is present on
`main`. Changing the Pages source earlier would leave no deployable workflow.

## Routine review flow

Start or refresh the long-lived preview branch:

```sh
git switch dev
git merge main
```

Make the proposed changes, then publish only the preview:

```sh
git push -u origin dev
```

The workflow compiles the LaTeX papers in both branches and deploys the combined
site. Review the result under `/dev/`. Preview HTML receives a visible warning
banner and a `noindex,nofollow` directive.

When the preview is approved, merge `dev` into `main` through the normal pull
request flow. The resulting `main` deployment moves the approved content to the
production root.

## Important behavior

- The development preview is public. Do not place secrets or sensitive draft
  material in it.
- Direct PDF links under `/dev/` do not carry the HTML preview banner; verify
  that the URL contains `/dev/`.
- A failed PDF build stops deployment, leaving the previously deployed
  production and preview content intact.
- Deployments are queued rather than cancelled so simultaneous `main` and `dev`
  pushes cannot race each other.
