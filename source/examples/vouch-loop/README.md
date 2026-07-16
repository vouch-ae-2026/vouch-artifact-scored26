# Vouch Loop Example

This directory holds a small end to end Vouch example. It contains one Lispex rule, one input datum, and a committed expected receipt. You can generate a fresh receipt into `receipts/current` and compare it against the committed one.

## Generate a receipt

With the native standalone binary

```sh
mkdir -p examples/vouch-loop/receipts/current
lispex diff-receipt --input examples/vouch-loop/inputs/refund-window.datum examples/vouch-loop/cases/refund-window.lspx > examples/vouch-loop/receipts/current/refund-window.json
```

With the npm package

```sh
lispex verify --source examples/vouch-loop/cases/refund-window.lspx examples/vouch-loop/receipts/current/refund-window.json
```

## Replay

```sh
lispex replay examples/vouch-loop --against examples/vouch-loop/receipts/current
```

## What a receipt does and does not show

A receipt is a record of an evaluation. It does not prove that the party who produced it acted honestly, that the inputs are authentic, who applied a decision, when it was applied, or that the rule is the one running in any deployment.
