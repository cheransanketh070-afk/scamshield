# Contributing to ScamShield

The most valuable contribution is **a scam pattern you have actually seen**, especially in a language other than English.

## Add a rule (no coding needed)

Rules live in `src/scamshield/data/patterns.json`. A rule looks like this:

```json
{
  "id": "payment.en.fee",
  "category": "payment",
  "lang": "en",
  "weight": 25,
  "title": "Asks for a small fee",
  "explain": "Advance fees are how prize, parcel, loan and job scams make money.",
  "patterns": ["\\b(processing|customs|redelivery) (fee|charge)s?\\b"],
  "examples": ["Pay a $1.99 redelivery fee"]
}
```

1. **id** is unique, in the form `category.lang.name`.
2. **weight** is 5 to 30. Soft signals get 5 to 15, strong ones 20 to 30. Use a negative number for reassuring signs.
3. **patterns** are Python regular expressions, case-insensitive. Keep them narrow: a false alarm on a normal message hurts trust.
4. **examples** are required. The test suite checks that every example triggers its own rule.
5. Use only anonymised, made-up examples. Never paste a real person's phone number, name or account.

Then run the tests:

```bash
python -m unittest discover -s tests -v
```

You can try a rule privately without editing the main file:

```bash
scamshield check --patterns my-pack.json "text to test"
```

See `data/example-pack.json` for a minimal pack.

## Native-speaker review

The Spanish, Hindi, Tamil and Sinhala packs are starter sets. If you speak these languages, please review the wording and tell us what we got wrong.

## Code changes

- Standard library only: the project promises zero runtime dependencies.
- Add a test for every behaviour change.
- Never log or store message content.

## Reporting a security issue

Open a private security advisory on GitHub rather than a public issue.
