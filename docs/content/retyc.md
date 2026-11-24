---
title: "Retyc"
description: "Rclone docs for Retyc"
versionIntroduced: "v1.77"
---

# Retyc

[Retyc](https://retyc.com) is a European file storage and transfer
service with end-to-end encryption. Files are encrypted on the client
with [age](https://age-encryption.org) using a post-quantum hybrid key
(MLKEM768-X25519), so the server only ever sees encrypted data.

Files are kept in storage spaces. Paths are specified as
`remote:space/path/to/file`, where `space` is the name of a storage
space. Listing the root of the remote shows the storage spaces.

Paths may be as deep as required, e.g. `remote:space/directory/subdirectory`.

## Configuration

The initial setup needs the existing passphrase of your Retyc encryption
key, so answer `y` and type it in when asked for it, and then
a login to Retyc which you approve in your browser. `rclone config`
walks you through it.

Here is an example of how to make a remote called `remote`.  First run:

```console
rclone config
```

This will guide you through an interactive setup process:

```text
No remotes found, make a new one?
n) New remote
s) Set configuration password
q) Quit config
n/s/q> n
Enter name for new remote.
name> remote
Option Storage.
Type of storage to configure.
Choose a number from below, or type in your own value.
[snip]
XX / Retyc end-to-end encrypted storage spaces
   \ (retyc)
[snip]
Storage> retyc
Option key_passphrase.
Passphrase of your existing Retyc encryption key.
This is the passphrase set when your Retyc account or key was created.
Type it in: a generated passphrase can't unlock the key.
The key decrypts your storage spaces. The passphrase never leaves this
machine.
Choose an alternative below.
y) Yes, type in my own password
g) Generate random password
y/g> y
Enter the password:
password:
Confirm the password:
password:
Edit advanced config?
y) Yes
n) No (default)
y/n> n
NOTICE: Open this link in a browser to log in to Retyc: https://login.example.com/device?user_code=ABCD-EFGH
NOTICE: Approve the login there, checking that the code shown is ABCD-EFGH
Log in to Retyc.

Open this link in a browser:

    https://login.example.com/device?user_code=ABCD-EFGH

and approve the login, checking that the code shown is ABCD-EFGH.

Confirm here once this is done.
y) Yes (default)
n) No
y/n> y
NOTICE: Waiting for the login to be approved...
Configuration complete.
Options:
- type: retyc
- key_passphrase: *** ENCRYPTED ***
- token: {"access_token":"XXX","token_type":"Bearer","refresh_token":"XXX","expiry":"2026-01-01T00:00:00.000000000Z"}
Keep this "remote" remote?
y) Yes this is OK (default)
e) Edit this remote
d) Delete this remote
y/e/d> y
```

The link and the code are made up for this example. Rclone shows the
real ones when you run it. Open the link in a browser, check that the
code shown there is the one rclone printed, approve the login, and only
then confirm in rclone.

The login has to be approved before the link expires, usually after a
few minutes. Rclone waits for the approval until then, and gives an
error if the link expired: run the configuration again to get a new
one.

`rclone config create` and `rclone config update` don't ask for the
confirmation: they print the link and the code, then wait for the
login to be approved. With `--non-interactive` the configuration is
made in two steps, the second one, run with `--continue`, waiting for
the approval.

The login can be done on a machine other than the one running rclone,
as it only needs a browser to open the link in.

The passphrase is stored in the config file
[obscured](/commands/rclone_obscure/), not encrypted. Use
[configuration encryption](/docs/#configuration-encryption) if you need
the config file to be protected.

To log in again, for example if the login has expired or been revoked,
run:

```console
rclone config reconnect remote:
```

Once configured you can then use `rclone` like this (replace `remote` with the
name you gave your remote):

List the storage spaces

```console
rclone lsd remote:
```

List all the files in a storage space called `space`

```console
rclone ls remote:space
```

To copy a local directory to a directory called `backup` in the storage
space `space`

```console
rclone copy /home/source remote:space/backup
```

### Storage spaces

The root of the remote lists the storage spaces of the account. Every
file and directory must be inside a storage space, so a file can't be
uploaded to the root.

Rclone can't create or remove a storage space. Create them with
Retyc, and use their names in the path. Trying to make a directory in
a storage space that doesn't exist, or to remove a storage space with
`rclone rmdir`, gives an error.

The remote can be rooted inside a storage space, e.g. `remote:space/directory`.
In that case the remote behaves as an ordinary directory tree.

### Modification times and hashes

Retyc stores modification times on files with a precision of 1
microsecond, and they can be changed without uploading the file again.
These are used to detect whether files need syncing or not.

Retyc doesn't support any hashes. The content is encrypted on the
client, so the server has nothing to compute a hash of. This means that
`rclone check` can only compare sizes, unless you use the `--download`
flag to download and compare the contents of the files.

### Restricted filename characters

Retyc encrypts file and directory names on the client, so it doesn't
restrict the characters in them. Rclone does join the names into
paths with `/`, so the following character is replaced.

| Character | Value | Replacement |
| --------- |:-----:|:-----------:|
| /         | 0x2F  | ／          |

File and directory names which are `.` or `..` will also be
[replaced](/overview/#encoding), and invalid UTF-8 bytes will also be
[replaced](/overview/#invalid-utf8).

### Server-side copy and move

Files can be copied and moved server-side, and directories can be moved
server-side, only within a single storage space. Between storage spaces
rclone falls back to downloading and uploading the data.

### Usage information

`rclone about` shows the usage of a storage space, so it needs the path
of a storage space, e.g.

```console
rclone about remote:space
```

It gives an error when run on the root of the remote.

### Limitations

- The size of a file has to be known before it is uploaded, so files
  can't be uploaded as a stream. Commands such as `rclone rcat` buffer
  the data before uploading it.
- Symbolic links in a storage space are ignored and don't show in
  listings.
- Listings are cached for about a minute. A change made to a storage
  space by another client, or by another rclone, can take about that long
  to show up.
- Unlocking the encryption key with the passphrase is slow, so it is
  unlocked once per remote by each rclone command. On Linux the unlocked
  key is also kept in the session keyring for 60 seconds, and rclone
  commands run within that time don't need to unlock it again.
- Replacing a file with a server-side copy makes the copy under a
  temporary name, starting with `.` and ending with `.partial`, next to
  the file, then renames it over the file.

<!-- autogenerated options start - DO NOT EDIT - instead edit fs.RegInfo in backend/retyc/retyc.go and run make backenddocs to verify --> <!-- markdownlint-disable-line line-length -->
### Standard options

Here are the Standard options specific to retyc (Retyc end-to-end encrypted storage spaces).

#### --retyc-key-passphrase

Passphrase of your existing Retyc encryption key.

This is the passphrase set when your Retyc account or key was created.
Type it in: a generated passphrase can't unlock the key.

The key decrypts your storage spaces. The passphrase never leaves this
machine.

**NB** Input to this must be obscured - see [rclone obscure](/commands/rclone_obscure/).

Properties:

- Config:      key_passphrase
- Env Var:     RCLONE_RETYC_KEY_PASSPHRASE
- Type:        string
- Required:    true

### Advanced options

Here are the Advanced options specific to retyc (Retyc end-to-end encrypted storage spaces).

#### --retyc-token

Login token as a JSON blob.

Properties:

- Config:      token
- Env Var:     RCLONE_RETYC_TOKEN
- Type:        string
- Required:    false

#### --retyc-url

URL of the Retyc API.

Properties:

- Config:      url
- Env Var:     RCLONE_RETYC_URL
- Type:        string
- Default:     "https://api.retyc.com"

#### --retyc-encoding

The encoding for the backend.

See the [encoding section in the overview](/overview/#encoding) for more info.

Properties:

- Config:      encoding
- Env Var:     RCLONE_RETYC_ENCODING
- Type:        Encoding
- Default:     Slash,InvalidUtf8,Dot

#### --retyc-description

Description of the remote.

Properties:

- Config:      description
- Env Var:     RCLONE_RETYC_DESCRIPTION
- Type:        string
- Required:    false

<!-- autogenerated options stop -->
