# Trust rubric (v1.1)

A level is a floor; the **score** is a number within a level that lets a platform rank, route and rate-limit
finders, and that sets the L2 floor. The rubric is deliberately simple so that two platforms compute the same
number from the same ledger, and so that a finder can predict what will raise it. It will be gamed; the
defences are listed at the end, and the first version of this rubric was revised because it failed them.

## Inputs

From the finder's [trust ledger](provenance.md#trust-ledger) for the statement's track, **after the verifier has
dropped every outcome entry whose countersignature does not verify under a key it has pinned, every entry that names
a key outside the finder's successor chain, and every entry for another track** ([VSLA-V-5](requirements.md)), over
a window of the last *W* counted entries **by countersigned `at`** (default `W = 50`), with every age measured from
the evaluation instant `t_eval` ([VSLA-V-7](requirements.md)):

| Symbol | Meaning |
|---|---|
| `n` | counted entries in the window: outcomes `accepted` (including `vouched`), `rejected`, `false-positive`, and the disqualifying outcomes. **Neutral** outcomes (`duplicate`, `withdrawn`, `reproduced-unresolved`) are excluded from the window entirely, so they can neither pump nor sink the score |
| `a` | outcomes `accepted` that are not `vouched` |
| `r_i` | the age in days of each `rejected` or `false-positive` entry |
| `x` | outcomes `non-authoritative-release`, `retracted`, `ledger-fork` (disqualifying) |
| `m` | distinct pinned countersigners, counted per operator: the name part of the keyid (`platform:acme.example` and `maintainer:acme.example` are one countersigner) |
| `o` | over-claims: entries where `claimed > verified` |
| `age` | days since the oldest counted entry in the window |

## Score

```
precision   P = a / n
breadth     B = min(1, m / 3)
seasoning   S = min(1, age / 90) · min(1, n / 10)
calibration C = max(0, 1 - 2·o / n)
recency     R = 1 - 0.5 · min(1, Σ_i exp(-r_i / 30))

score = 0 if x > 0 or o / n ≥ 1/2, else  P · (0.5 + 0.2·B + 0.2·S + 0.1·C) · R
```

What changed from v1.0 and why: duplicates no longer count as positives (a finder could farm them from public
cases); withdrawing is no longer penalised (it is the behaviour you want); recency sums every rejection with
decay instead of looking only at the most recent one (ten rejections last month are not one); calibration is
twice as steep and disqualifies at half the window (over-claiming every statement cost 0.1 before); and the
floors gained a hard age gate (two colluding keys and five entries could reach the floor on day zero).

The shipped example ledger ([`schema/examples/ledger.json`](../../schema/examples/ledger.json)): 13 entries, of
which 2 duplicates are excluded, leaving `n = 11`; 10 accepted; 1 rejection 83 days ago; 3 pinned
countersigners; 138 days of history; 1 over-claim. `P = 0.909`, `B = 1`, `S = 1`, `C = 0.818`, `R = 0.969`:
`0.909 · (0.5 + 0.2 + 0.2 + 0.082) · 0.969 = 0.865`. The reference verifier and the examples agree on this
number to four places.

## Floors

| Floor | Default | Meaning |
|---|---|---|
| `l2_floor` | 0.60 | minimum score for the Identity pillar to reach L2 |
| `l2_min_entries` | 5 | a finder with fewer counted entries cannot reach L2, whatever its score |
| `l2_min_countersigners` | 2 | at least two distinct pinned countersigners |
| `l2_min_age_days` | 30 | the oldest counted entry is at least this old; a hard gate, not a term in the score |

A platform publishes its floors and the countersigners it pins in its policy ([VSLA-P-5](requirements.md)).
A stricter platform may raise them; a platform may not lower `l2_min_entries` below 3 or `l2_min_age_days`
below 14.

## Bootstrapping

A new finder has no ledger and so no L2. That is intended: L2 is earned. The path is to disclose at L1 to
platforms that accept L1 (qudisclose does, into the `scheduled` lane with human review of the patch), collect
countersigned outcomes, and cross the floor after the age gate. A platform MAY let a maintainer vouch for a
finder (a countersigned `accepted` entry with `vouched: true`), which counts toward `n` and `m` but not toward
`a`. An honest finder that discloses to a single platform has one countersigner and cannot reach L2 at that
platform until a maintainer countersigns directly or vouches; that is a cost of the two-countersigner floor,
and the spec accepts it rather than count self-countersigned entries twice.

## What the score is not

It is not a reputation market and it is not transferable: it belongs to a key, and a key belongs to one
finder run by one operator. A key is rotated with a signed `successor` entry (old and new keys sign; the new
key inherits the window) and revoked with a `revoke` entry signed by the operator; a platform that sees the
revocation stops counting statements dated after it ([VSLA-F-20](requirements.md)). It is not a prediction:
a level is evidence about *this* disclosure, and a high score says the finder has been right, not that it will
be. It is not a credential to present to a bounty program or a CNA: a ledger is only as good as the
countersigners the reader has pinned, and a reader who pins none should read it as L1.

## Known ways to game it, and what the rubric does about them

| Attack | Defence |
|---|---|
| Two colluding keys countersign each other | the verifier counts only pinned countersigners, per operator (V-5); the age gate |
| Presenting another finder's published ledger | entries name the finder key; a verifier drops the rest |
| Spending Finding history on the Patch track | ledgers are per track; a verifier drops entries for another track |
| Ordering a long history so rejections fall out of the window | the window is by countersigned `at`, which the finder cannot choose |
| Omitting a platform's negative entry on the next submission | the platform checks that every entry it countersigned is included, so the omission is a `ledger-fork` there |
| Rotating to a fresh key to shed history | a `successor` entry carries the history forward; a fresh key without one starts at zero, by design |
| Verifying at a convenient time so a rejection has decayed | every age is measured from `t_eval`, which the anchor fixes |
| Farming `duplicate` against public cases | duplicates are neutral and excluded |
| Over-claiming L3 on every statement | disqualified at `o/n ≥ 1/2` |
| Aging a bad streak out with volume | recency sums decayed rejections; the window counts only non-neutral entries |
| A long honest run, then one harmful merge | `retracted` is disqualifying and retroactive (VSLA-P-15); the source-only scope rule (VSLA-F-18); a level never means "merge unread" |
| A platform that writes `false-positive` for a finder it dislikes | every negative outcome carries a signed reason; other platforms decide whether to pin that platform |
