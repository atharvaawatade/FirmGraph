# What's Done — in plain English

> FirmGraph checks a device's firmware for security problems — on **your own computer**,
> without your firmware ever leaving it. This page says, in simple words, what works today.

---

## The one-line version

You give FirmGraph a firmware file. It opens it up, lists the software inside, finds the known
security holes — and then does the important part: it tells you the **handful that actually
matter on your device**, instead of drowning you in thousands. Then it writes the paperwork you
need for the new EU security law (the CRA).

---

## What works today — step by step

1. **Open the firmware.** Unpacks the file and **honestly says how much it got out** — 94%? or
   only 1% because it's encrypted? No pretending.
2. **List the parts.** Makes an "ingredients label" of every piece of software inside.
3. **Find known problems.** Matches those parts against the public list of known security holes.
4. **Cut the noise.** The smart part — see below.
5. **Rank what's left.** Puts the scariest, most-likely-to-be-attacked ones at the top.
6. **Write the report + evidence.** A clean report a human can read, a machine-readable evidence
   pack, and the CRA paperwork.

---

## The smart part: cutting the noise (this is what's new)

A normal scanner shouts *"your device has 3,000 problems!"* — which is useless, because most
aren't real **on your device**. FirmGraph now has three checks that rule out the fake ones, and
**each one shows its proof**:

1. **"Is that part even switched on?"**
   The Linux core gets blamed for thousands of problems, but most are in features your device
   never turned on — like a *Bluetooth* flaw on a device that has *no Bluetooth*. FirmGraph reads
   the device's own settings and crosses those off, showing the exact setting as proof.

2. **"Is that part actually used?"**
   Firmware often ships spare parts that nothing runs. If a risky library is just sitting there
   and no program uses it, FirmGraph lowers its priority — and shows what's connected to what.

3. **"Can an attacker reach it from outside?"**
   A hole in something facing the internet (like the login service) is far worse than one buried
   deep inside. FirmGraph finds the internet-facing services that are switched on and pushes their
   problems to the top.

**The result:** *"3,000 problems"* becomes *"here are the ~12 that actually matter — and here's
why the rest don't."*

---

## The report

It leads with one simple picture:

> **Found → Ruled out (with proof) → What's left to fix** — and the % of noise removed.

The scary stuff is at the top. Nothing is ever deleted — the ruled-out items stay listed with
their reasons, so an auditor can see the whole story.

---

## Your firmware never leaves your machine

This is a promise you can **check yourself**. Run `./prove-zero-egress.sh` and it proves — three
different ways — that FirmGraph sends nothing, anywhere. Your firmware is your secret; it stays
your secret.

---

## How solid is it?

- **86 automated tests, all passing.**
- Clean code checks (style + types), zero warnings.
- Every claim in the docs matches what the code actually does — if they ever disagree, we treat
  that as a bug and fix it.

---

## What's *not* done yet (being honest)

- We haven't run the noise-cutting on a big **real-world** image end-to-end yet — only on careful
  test cases. That's the next proof.
- **Deeper analysis** (tracing the exact path an attacker's input would take) is planned, not built.
- A couple of extras — a second scanning engine and the optional AI explainer — aren't finished.

---

**The simple truth:** the core works, it's honest about its limits, and the thing that makes it
special — cutting thousands of false alarms down to the few real ones, *with proof*, *without ever
taking your firmware* — is built and tested.
