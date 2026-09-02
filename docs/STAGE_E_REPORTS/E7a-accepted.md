# E7a acceptance — learned triage model v1

**Accepted:** 2026-09-02. **Implementation branch:** `feat/e7a-model-v1`. **Implementation commit:** `fb24aef`. **Implementation merge:** `8337490`. **Independent-test branch:** `test/e7a-feature-contract`. **Test commit:** `3b5ddf0`. **Test merge:** `f43d757`. **Push:** none.

## Outcome

E7a is accepted and merged locally. The optional, local scikit-learn classifier trains through the real generator/analyzer pipeline, consumes one shared ordered 21-field rule-fact vector at training and inference, records dataset/model provenance, and renders a learned advisory beside the unchanged rule verdict on Findings and Incidents. Missing dependencies, model files, or valid provenance produce a visible unavailable state with null opinion fields; findings, incidents, cases, and decision fields remain intact.

The wall remains structural: disposition, advisory/model output, prose, severity and overrides, priority, eligibility, and execution fields are forbidden feature inputs. The model is unreachable from the detector, severity, priority, eligibility, and execution import graphs. A confirmed prediction mirrors the rule band for comparison; false-positive and benign-expected predictions are downgrade-only advice and never alter the rule-owned result.

## Training evidence

| Check | Result |
|---|---|
| clean Python 3.13 environment | installed the pinned `scikit-learn==1.7.2`; optional runtime behavior also tested without it |
| fresh training | 434 labeled rows in 13.03 s; generator seeds 20260902–20260915; six scenarios; two normalized formats |
| labels | 224 confirmed, 126 false-positive, 84 benign-expected |
| stratified cross-validation | five folds; macro-F1 mean 0.9568, minimum 0.9121, maximum 1.0000 |
| real local history | no disposition labels existed, so none were invented; 2,501 unlabeled events were provenance context only |
| artifact location | gitignored `console/.soc/models/` with integrity-bound provenance sidecar; no model artifact tracked |

## Mutation and independent contract evidence

The implementation worker made two real breaking mutations and observed the wall fail before restoring them: disposition leakage into features reduced the wall to 100/101 and failed its unit test; importing the model through the priority path triggered the direct and transitive import guards, including the scikit-learn reachability check.

The separate Codex test card added 10 stdlib-only tests without changing production code. They cover deterministic vectors over real generator subprocess batches and three classes/seeds, every forbidden field singly and together, the unique shared extractor and ordering, all three prediction contracts, all dependency/artifact failure modes, byte-identical rule/incident/case snapshots across attach and model kill, protected projection isolation, and advisory non-persistence. Its first run exposed a malformed test fixture and failed before the fixture was corrected; the final suite is green.

## Coordinator post-merge gates

| Check | Result |
|---|---|
| `python3 -m unittest tests.test_e7a_feature_contract -v` | 10/10 passed |
| `python3 tests/test_stage_e_wall.py` | 101/101 passed |
| `python3 console/test_console.py` | full suite green |
| `npm --prefix web test` | 43/43 files, 278/278 tests passed |
| `npm --prefix web run build` | passed |
| `python3 tests/eval/run_eval.py` | 20/20; precision, recall, F1 all 1.000 |
| `sha256sum anomaly_detector.py` | exact frozen SHA-256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| `git diff --check` | passed |
| `graphify update .` | completed; 3,742 nodes, 6,533 edges, 229 communities |

Graphify again reported the known partial-parse warning for `web/src/pages/Incidents.tsx`; the authoritative TypeScript production build passed. Web tests emitted existing React `act(...)` and router-future warnings but had zero failures.

E7a is now closed. E8 may extend and then freeze the benchmark referee; E7b may not begin before that referee is accepted.
