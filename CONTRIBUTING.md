# Contributing

Thanks for taking the time to help.

This repository is a read-only copy of our internal repository, refreshed on every change. Nothing
is merged here directly: the next refresh would overwrite it.

- **Issues** are welcome here, for bugs, false positives or false negatives of the masking, and
  ideas. Please never paste a real secret or real personal data in an issue.
- **Pull requests** are welcome too. We copy each one to our internal repository, review it there
  and, once merged, it comes back here with the next refresh, with you as its author. We then
  close the pull request with a link to the commit.

Before opening a pull request, run `make verify` (gofmt, go vet, go test). A new detection rule
needs its case in `internal/mask/mask_test.go`.
