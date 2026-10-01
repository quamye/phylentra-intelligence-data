# PHYLENTRA intelligence data

Public KEV and EPSS snapshots for the PHYLENTRA prototype. This repository is not connected to Vercel and does not deploy the application.

The application reads a commit SHA of this repository. It does not call CISA or FIRST when a visitor opens a page.

## What is published

Each commit that changes `data/` contains a `data/manifest.json` and, when validation produced a new payload, files under `data/generations/<timestamp>/`. Readers resolve one commit and read every file from that commit.

KEV payloads keep `cveID`, `dateAdded`, and `knownRansomwareCampaignUse`, plus the catalog version and `dateReleased`. Those fields come from the CISA catalog, which is distributed under [CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt). `dateAdded` is the date CISA added the CVE to the catalog. This repository does not use CISA or DHS marks.

EPSS payloads keep the CVE id, probability, percentile, and the score date returned by FIRST. FIRST grants public use of EPSS scores and asks for attribution: [https://www.first.org/epss](https://www.first.org/epss), or Jacobs, Romanosky, Edwards, Roytman, and Adjerid (2021), Exploit Prediction Scoring System, Digital Threats: Research and Practice, 2(3). Fetching a score again does not change its score date.

The publisher reads the public CCCS Atom feed only to discover CVE identifiers. It does not publish advisory titles, summaries, or HTML. Commercial reuse of the CCCS feed text is still unresolved, so that text is not in this repository.

## Schedule

The workflow runs daily at 11:17 UTC, and it can be started with `workflow_dispatch`. GitHub runs a schedule only from the default branch. During busy periods GitHub can delay a run or drop it. A missed or failed run does not delete the last manifest. The next successful run writes a new generation. A public repository can also disable a schedule after 60 days without repository activity; a successful daily commit is repository activity.

There is no `push` trigger. The publishing job is the only job with `contents: write`. Its commit uses the workflow token, which does not start this workflow again.

## Growth

A KEV file is added only when the slim catalog changes. An EPSS file is added when a run publishes scores, including a partial run. Removing an old file from the branch tip does not remove the blob from Git history.

For a few dozen advisory CVEs whose scores change daily, the EPSS history is on the order of a few megabytes a year. A full slim KEV copy is about 150 kilobytes; it is stored again only when the catalog content changes. Manifest commits are about a kilobyte each, once a day. These are estimates, not a quota. The full EPSS corpus and the full KEV prose catalog are not stored.

## Failures

A complete KEV or EPSS failure updates the attempt time and leaves the previous payload path in place. A partial EPSS result publishes the validated rows, keeps older rows with their original fetch time and score date, and marks the missing rows as stale or failed. A CVE omitted by a finished lookup is `no-record`. A CVE the application sees that this snapshot did not request stays pending in the application. Neither case is a customer-exposure result.
