# The three layers in depth

I'll use one example the whole way through: your app receives the SMS *"You won Rs 50,000, click to claim"* and decides it is SPAM. That verdict has to be saved in `message_records`, and we want nobody to be able to change it later.

---

# Layer 1: The gatekeeper

## The problem it solves

Without a gatekeeper, any part of your code could write anything to the database, for example `insert_one({"classification": "SAFE", ...})`. A bug or an attacker could then write fake or wrong records.

## What it is

It is one function, `secure_database_operation`. The rule is that **nobody writes to the history collections except through this function.** Your semantic service already follows that rule.

Every call looks like this:

```python
secure_database_operation(
    actor="APPLICATION_SERVICE",       # who I am
    operation="CREATE_MESSAGE",        # what I want to do
    resource="message_records",        # where
    data={...},                        # the content
    credential="<my secret password>", # proof that I am who I say
)
```

## The five checks, one at a time

**Check 1: Authentication ("prove who you are").**
Anyone can *say* they are `APPLICATION_SERVICE`. The gatekeeper checks the password you sent against the one stored in the environment variable `ACTOR_SECRET_APPLICATION_SERVICE`. If it's wrong, missing, or that actor has no password configured, the answer is always the same: "Authentication failed". It never says which part was wrong, so an attacker learns nothing.

**Check 2: Authorization ("are you allowed to do this?").**
Knowing who you are isn't enough. There is a permission table:

```
CREATE_MESSAGE  -> allowed for APPLICATION_SERVICE, ADMINISTRATOR, ...
DELETE_HISTORY  -> allowed for: nobody (empty list)
UPDATE_HISTORY  -> allowed for: nobody
```

Each action is also tied to specific collections. `CREATE_MESSAGE` only works on `message_records`. If you try `CREATE_MESSAGE` on `spam_patterns`, it is refused. So even the administrator can't delete or edit history through this function, because that action simply doesn't exist for anyone.

**Check 3: Validation ("is the content sensible?").**
- **Whitelist:** each action accepts only certain fields. For `CREATE_MESSAGE` these are the message text, `classification`, `risk_score`, `semantic_group_id`, `processing_path` and `metadata`. Anything else is rejected.
- **Server-only fields:** if the caller sends `integrity_hash`, `timestamp`, `chain_seq` or `previous_hash`, it is rejected outright. Those belong to the server.
- **Value checks:** the text can't exceed 10,000 characters, `risk_score` must be 0 to 100, and `classification` must come from an allowed list. Embeddings must be ordinary finite numbers, and `metadata` can't be huge.

**Check 4: The server builds the record.**
The caller only supplies the content. The gatekeeper adds everything that matters for trust: a random `message_id`, a fingerprint of the SMS text (`message_hash`), the timestamp, and the chain fields (Layer 2). So the caller can't backdate a record or forge an ID.

**Check 5: Save and log.**
The record is inserted, and an `OPERATION_EXECUTED` entry is added to `audit_logs`, noting who did what. If any check fails, nothing is saved. Instead, an `ACCESS_DENIED` entry is logged with the reason, and the caller gets an error.

## What it stops

Anyone trying to forge or change history *through your app*: a bad request, a stolen actor name without the password, or a bug that sends garbage.

## Its weakness

It is only Python code inside your program. Any other code in the same program could import the database connection and skip the gatekeeper entirely. This is why we need Layer 3.

---

# Layer 2: The hash chain

## The problem it solves

Suppose someone edits the database directly, without going through your app. Layer 1 never sees it. We need a way to *notice*. Since we can't always stop it, we make it detectable.

## First, what a hash is

A hash function turns any data into a fixed-length "fingerprint". The rules that matter:

- The same data always gives the same fingerprint.
- Change a single character and the fingerprint is completely different.
- You can't work backwards from the fingerprint to the data.

For illustration (shortened, not real values):

```
hash("SPAM") -> 9f3a...
hash("SAFE") -> 1c72...    (totally different)
```

## The secret key

A plain hash has a weakness: anyone can compute it. So an attacker who changes a record can just recompute the fingerprint too. We fix this with **HMAC**, which mixes a secret key into the hash. The key (`INTEGRITY_HMAC_KEY`) lives in your `.env`, not in the database. Without it, nobody can make a valid fingerprint, even with full database access.

## What a record looks like

```json
{
  "message_id": "9f2c...",
  "message_hash": "5b1e...",        // fingerprint of the SMS text (the text itself isn't stored here)
  "classification": "SPAM",
  "risk_score": 92,
  "record_type": "MESSAGE_CREATED",
  "timestamp": "2026-09-24T05:40:11+00:00",
  "chain_seq": 7,                   // position: this is record number 7
  "previous_hash": "a41d...",       // record 6's stamp
  "integrity_hash": "c93b..."       // this record's stamp
}
```

## How the stamp is made

```
integrity_hash = HMAC( secret key,  previous_hash + every other field of the record )
```

Two details explain why this works reliably:

- **Canonical JSON.** Before hashing, the record is written in one fixed format (keys sorted, no extra spaces), so the same record always gives exactly the same stamp no matter how the fields were ordered.
- **Left out of the stamp:** `_id` (MongoDB adds it after saving), and `integrity_hash` itself (a value can't contain its own fingerprint).

Because each stamp includes the *previous* stamp, the records form a chain:

```
Record 1: previous = GENESIS ->  stamp A
Record 2: previous = A       ->  stamp B
Record 3: previous = B       ->  stamp C
```

## The check, and what it catches

The verifier goes through the records in order and, for each one, does three things:
1. Recompute the stamp from its contents and compare it with the stored stamp.
2. Check that `previous_hash` equals the earlier record's stamp.
3. Check that `chain_seq` counts 1, 2, 3 with no gaps.

**Example: someone changes record 7 from SPAM to SAFE.**
- The verifier recomputes record 7's stamp from the new contents and gets something different from the stored `c93b...`. **Record 7 fails.**
- Record 8 still points to `c93b...`, and record 7's stored stamp is still `c93b...`, so the link looks fine. That's why the failure points at exactly record 7.

**What if the attacker also changes record 7's stamp?** Without the key they can only guess, and a wrong stamp fails on record 7. Even with the key, once record 7's stamp changes, record 8's `previous_hash` no longer matches, so they would have to redo every later record too.

| Tampering | What happens |
|---|---|
| Edit a record | That record's stamp doesn't match |
| Delete a record in the middle | Gap in `chain_seq` and a broken link |
| Insert a fake record | Invalid stamp (they don't have the key) |
| Delete the newest records | **Not detected.** A shorter chain still verifies |

## Keeping it one single chain

If two messages arrive at the same instant, both might read "latest is record 6" and both try to save as record 7, forking the chain. To prevent that, `chain_seq` has a **unique index**. An index is a lookup list, and "unique" means the database refuses duplicates. The first insert wins. The second gets a duplicate error, re-reads the newest record (now 7) and saves as 8. It retries up to 5 times. If the database can't be read at all, the code raises an error, and it doesn't quietly restart the chain.

## Its weakness

It only reports that something changed. It doesn't prevent the change, and it needs the key to stay secret.

---

# Layer 3: Atlas permissions

## The problem it solves

Layer 1 is code that can be bypassed, and Layer 2 only detects. We want something that **physically prevents** editing or deleting history even if someone bypasses our code.

## How it works

Whenever any program connects to MongoDB Atlas, it logs in as a *database user*. Every command it sends (`find`, `insert`, `update`, `delete`) is checked by the **Atlas server** against that user's roles **before it runs**. Our Python code has no way around this, because the check happens on Atlas's side.

## What we set up

- **A custom role, `scamshield_app_role`**, allowing:
  - `read`: look at records
  - `insert`: add records
  - `createIndex`: create the indexes at startup
  - `update` only on `senders` and `message_analyses`, which your reputation code needs to change
- **A user, `scamshield_app`**, with only that role. We removed Atlas's default "read and write to any database" role, because when a user has several roles, Atlas uses the highest permission.
- **Your app logs in as this user**, via `MONGODB_URI`.

So on `message_records`, `spam_patterns`, `pattern_events` and `audit_logs`, the app can add and read but **can never update or delete**. When we tested, Atlas answered `user is not allowed to do action [update]`.

## What it stops

Someone who steals the app's database password, or who finds a way around the Python gatekeeper. Even with the app's own login, the edit is refused.

## Its weakness

Your own Atlas account and the `developer` user still have full rights, so an admin can edit records. That is where Layer 2 comes in.

---

# Putting it together with one attacker at a time

Goal for every attacker: change record 7 from SPAM to SAFE.

| Attacker | What happens |
|---|---|
| Sends a bad request through your app | **Layer 1** refuses (no such action, or the field isn't allowed). An `ACCESS_DENIED` entry is logged. |
| Steals the app's database password and connects directly | **Layer 3**: Atlas refuses the update. |
| Has admin rights and edits it in Atlas | The edit goes through, but **Layer 2** shows record 7 fails verification. |
| Has admin rights **and** your secret key | Nothing stops them, because they can recompute every stamp. That is the limit of the design. |

So each layer covers a gap that the others leave:
- **Layer 1** controls what comes in through the app.
- **Layer 3** limits what the app's own login can do.
- **Layer 2** lets you prove afterwards whether the data was changed, whoever did it.

If any part still doesn't click, tell me which one and I'll go through it step by step with the actual code lines.