# bd-2hqd.3 Hardening Verification Summary

## Scope
Hardening lane for transplant lockfile generator reliability under manifest drift.

## Change
- transplant/generate_lockfile.sh now fails closed when manifest entries are missing.
- tests/test_transplant_lockfile_scripts.py includes regression for missing manifest entry behavior.

## Validation
1. python3 -m unittest tests/test_transplant_lockfile_scripts.py -v
2. python3 -m unittest tests/test_check_foundation_e2e_bundle.py -v

## Exit Codes
- command 1: 0
- command 2: 0

## Outcome Snippets
### command 1
10:Ran 7 tests in 0.734s
12:OK

### command 2
9:Ran 6 tests in 0.006s
11:OK

## Evidence Files
- unittest_transplant_lockfile_scripts.log
- unittest_transplant_lockfile_scripts.exit
- unittest_foundation_e2e_bundle.log
- unittest_foundation_e2e_bundle.exit
