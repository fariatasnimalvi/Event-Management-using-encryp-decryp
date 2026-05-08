# CSE447 Secure Event/Club Management System — MongoDB Version

This is the MongoDB rebuild of the secure Event/Club Management System.

## Features Included

- Login and registration
- Encrypted user information before MongoDB storage
- Password hashing and salting
- Two-factor authentication
- RSA encryption from scratch
- ECC encryption from scratch
- No symmetric encryption for data encryption
- Key management module
- Key generation, storage, wrapping, and rotation
- Encrypted posts and profiles
- MAC/HMAC integrity checking
- Role-Based Access Control
- Secure cookie-based session handling
- MongoDB collections instead of SQL tables

## Requirements

Install Python and MongoDB Community Server first.

Then install Python packages:

```bash
pip install -r requirements.txt
```

## Start MongoDB

On Windows, MongoDB usually runs automatically as a service after installation.

You can check by opening Command Prompt and running:

```bash
mongosh
```

If it connects, MongoDB is running.

## Run Project

```bash
python app.py
```

If Python command does not work on Windows, use:

```bash
py app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Admin Account

Register with username:

```text
admin
```

That account becomes admin automatically.

Any other username becomes a regular user.

## MongoDB Database

Database name:

```text
cse447_secure_event_club
```

Collections:

- keys
- users
- posts
- sessions

Use MongoDB Compass to view encrypted stored data.

## Important Demo Points

In MongoDB Compass, show:

- `users` collection: encrypted user fields, salted password hash, encrypted 2FA secret, MAC
- `posts` collection: encrypted title/body and MAC
- `keys` collection: RSA and ECC keys, active/rotated status, wrapped private keys
- `sessions` collection: active secure sessions

## Reset Database

To reset everything, open MongoDB Compass and delete the database:

```text
cse447_secure_event_club
```

Then run the project again.
