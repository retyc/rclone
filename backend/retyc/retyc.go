// Package retyc provides an interface to Retyc end-to-end encrypted storage.
package retyc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/bucket"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/random"
	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/auth"
	retycconfig "github.com/retyc/retyc-cli/core/config"
	"github.com/retyc/retyc-cli/core/diag"
	"github.com/retyc/retyc-cli/core/service"
	"github.com/retyc/retyc-cli/core/vfs"
	"golang.org/x/oauth2"
)

const (
	defaultURL = "https://api.retyc.com"
	// keyringTTL is how long the unlocked key stays in the session keyring,
	// in seconds: the default of the retyc command line tool, which shares it.
	keyringTTL = 60
	// defaultPollInterval is the pause between two polls of the device
	// login when the identity provider does not ask for one.
	defaultPollInterval = 5 * time.Second
	// defaultDeviceExpiry is how long a device login can be approved for
	// when the identity provider does not say: the default of the retyc
	// command line tool.
	defaultDeviceExpiry = 5 * time.Minute
	// pollState prefixes the config state that waits for the device login.
	pollState = "poll,"
	// defaultEncoding is the default of the encoding option. Names are
	// encrypted on the client so the API accepts any byte, but they are
	// joined into slash separated paths.
	defaultEncoding = encoder.EncodeSlash |
		encoder.EncodeDot |
		encoder.EncodeInvalidUtf8
)

var (
	errNoSpace         = errors.New("files and directories must be inside a storage space")
	errCantCreateSpace = errors.New("storage space not found: creating storage spaces is not supported")
	errCantRemoveSpace = errors.New("removing storage spaces is not supported")
	errUnknownSize     = errors.New("can't upload files of unknown size")
	errLoginExpired    = errors.New("the login link expired before the login was approved: run the configuration again")

	// diagOnce routes the messages of the Retyc libraries to the rclone log.
	diagOnce sync.Once

	// connsMu guards conns and the users of every conn.
	connsMu sync.Mutex
	// conns holds the connection of each remote in use in the process.
	conns = map[connKey]*conn{}
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "retyc",
		Description: "Retyc end-to-end encrypted storage spaces",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{{
			Name: "key_passphrase",
			Help: `Passphrase of your existing Retyc encryption key.

This is the passphrase set when your Retyc account or key was created.

The key decrypts your storage spaces. The passphrase never leaves this
machine.`,
			IsPassword: true,
			NoGenerate: true,
			Required:   true,
			Sensitive:  true,
		}, {
			Name:      config.ConfigToken,
			Help:      "Login token as a JSON blob.",
			Advanced:  true,
			Sensitive: true,
		}, {
			Name:     "url",
			Help:     "URL of the Retyc API.",
			Default:  defaultURL,
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default:  defaultEncoding,
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	KeyPassphrase string               `config:"key_passphrase"`
	URL           string               `config:"url"`
	Enc           encoder.MultiEncoder `config:"encoding"`
}

// Fs represents the storage spaces of a Retyc account
type Fs struct {
	name     string       // name of this remote
	root     string       // the path we are working on, without leading or trailing /
	opt      Options      // parsed options
	features *fs.Features // optional features
	conn     *conn        // connection shared with the other Fs of the remote
	vfs      *vfs.FS      // file tree of the storage spaces, from conn
	shutdown sync.Once    // releases conn once
}

// connKey is what determines the connection of a remote
type connKey struct {
	name       string // name of the remote
	url        string // URL of the API
	passphrase string // passphrase of the encryption key, revealed
}

// conn is the connection to Retyc of a remote. All the Fs of a remote
// share it, so they unlock the encryption key once and see each other's
// changes through a single listing cache.
type conn struct {
	key   connKey
	ready chan struct{} // closed once vfs or err is set
	vfs   *vfs.FS
	err   error
	users int // Fs using vfs, guarded by connsMu
}

// getConn returns the connection for key and counts one more user of it,
// who must call release when done.
//
// The connection is made with newVFS when the process has none for key.
// Concurrent calls for the same key wait for that single newVFS and share
// its error, which leaves nothing behind.
func getConn(ctx context.Context, key connKey, newVFS func() (*vfs.FS, error)) (*conn, error) {
	for {
		connsMu.Lock()
		c := conns[key]
		if c == nil {
			c = &conn{key: key, ready: make(chan struct{})}
			conns[key] = c
			connsMu.Unlock()
			c.vfs, c.err = newVFS()
			connsMu.Lock()
			if c.err != nil {
				delete(conns, key)
			} else {
				c.users++
			}
			connsMu.Unlock()
			close(c.ready)
			if c.err != nil {
				return nil, c.err
			}
			return c, nil
		}
		connsMu.Unlock()
		select {
		case <-c.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if c.err != nil {
			return nil, c.err
		}
		connsMu.Lock()
		if conns[key] == c {
			c.users++
			connsMu.Unlock()
			return c, nil
		}
		// Its last user released it in the meantime: make a new one
		connsMu.Unlock()
	}
}

// release counts one user less of c, closing it after the last.
func (c *conn) release() error {
	connsMu.Lock()
	c.users--
	last := c.users == 0
	if last && conns[c.key] == c {
		delete(conns, c.key)
	}
	connsMu.Unlock()
	if last {
		return c.vfs.Close()
	}
	return nil
}

// Object describes a file in a storage space
type Object struct {
	fs      *Fs      // what this object is part of
	remote  string   // the remote path
	spaceID string   // ID of the storage space holding the file
	path    string   // absolute path of the file in the storage space
	node    vfs.Node // the file as last read from the API
}

// diagWriter writes the messages of the Retyc libraries to the rclone log.
type diagWriter struct{}

// Write logs p, a whole message, as a warning or as debug.
func (diagWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	switch {
	case msg == "":
	case strings.HasPrefix(msg, "warning:"):
		fs.Logf(nil, "retyc: %s", msg)
	default:
		fs.Debugf(nil, "retyc: %s", msg)
	}
	return len(p), nil
}

// baseURL returns the URL of the API from the config
func baseURL(m configmap.Getter) string {
	u, _ := m.Get("url")
	if u == "" {
		u = defaultURL
	}
	return strings.TrimRight(u, "/")
}

// Config logs in to Retyc with the OAuth device flow and stores the token.
func Config(ctx context.Context, name string, m configmap.Mapper, configIn fs.ConfigIn) (*fs.ConfigOut, error) {
	client := fshttp.NewClient(ctx)
	switch {
	case configIn.State == "":
		if token, err := oauthutil.GetToken(name, m); err == nil && token.RefreshToken != "" {
			return fs.ConfigConfirm("refresh", true, "config_refresh_token", "Already have a token - refresh?")
		}
		return fs.ConfigGoto("login")
	case configIn.State == "refresh":
		if configIn.Result == "false" {
			return nil, nil
		}
		return fs.ConfigGoto("login")
	case configIn.State == "login":
		oidc, err := api.FetchOIDCConfig(ctx, baseURL(m), client)
		if err != nil {
			return nil, fmt.Errorf("failed to read login config: %w", err)
		}
		device, err := auth.RequestDeviceCode(ctx, *oidc, client)
		if err != nil {
			return nil, fmt.Errorf("failed to start login: %w", err)
		}
		verificationURL := device.VerificationURIComplete
		if verificationURL == "" {
			verificationURL = device.VerificationURI
		}
		// The question below is answered without being shown by
		// "rclone config create" and "rclone config update", so the link
		// is logged as well.
		fs.Logf(nil, "Open this link in a browser to log in to Retyc: %s", verificationURL)
		fs.Logf(nil, "Approve the login there, checking that the code shown is %s", device.UserCode)
		expiresIn := time.Duration(device.ExpiresIn) * time.Second
		if expiresIn <= 0 {
			expiresIn = defaultDeviceExpiry
		}
		// The device code is carried by the state so the login can be
		// completed by a later, non-interactive, call.
		state := loginState{
			interval:   time.Duration(device.Interval) * time.Second,
			expiry:     time.Now().Add(expiresIn),
			deviceCode: device.DeviceCode,
		}.String()
		return fs.ConfigConfirm(state, true, "config_device_login", fmt.Sprintf(`Log in to Retyc.

Open this link in a browser:

    %s

and approve the login, checking that the code shown is %s.

Confirm here once this is done.`, verificationURL, device.UserCode))
	case strings.HasPrefix(configIn.State, pollState):
		if configIn.Result == "false" {
			return nil, errors.New("login cancelled")
		}
		login, err := parseLoginState(configIn.State)
		if err != nil {
			return nil, err
		}
		oidc, err := api.FetchOIDCConfig(ctx, baseURL(m), client)
		if err != nil {
			return nil, fmt.Errorf("failed to read login config: %w", err)
		}
		pollCtx, cancel := context.WithDeadline(ctx, login.expiry)
		defer cancel()
		// expired reports whether the device code expired, rather than
		// the caller giving up.
		expired := func() bool {
			return ctx.Err() == nil && pollCtx.Err() != nil
		}
		fs.Logf(nil, "Waiting for the login to be approved...")
		interval := login.interval
		for {
			token, err := auth.PollToken(pollCtx, *oidc, login.deviceCode, client)
			switch {
			case errors.Is(err, auth.ErrDeviceCodeExpired) || (err != nil && expired()):
				return nil, errLoginExpired
			case errors.Is(err, auth.ErrAccessDenied):
				return nil, errors.New("login refused in the browser")
			case errors.Is(err, auth.ErrSlowDown):
				interval += defaultPollInterval
			case err != nil:
				return nil, fmt.Errorf("login failed: %w", err)
			case token != nil:
				return nil, oauthutil.PutToken(name, m, token, true)
			}
			select {
			case <-pollCtx.Done():
				if expired() {
					return nil, errLoginExpired
				}
				return nil, ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	return nil, fmt.Errorf("unknown state %q", configIn.State)
}

// loginState is the device login that the poll config state waits for
type loginState struct {
	interval   time.Duration // pause between two polls
	expiry     time.Time     // when the device code expires
	deviceCode string        // code the token is polled with
}

// String encodes s as a config state
func (s loginState) String() string {
	return pollState +
		strconv.Itoa(int(s.interval/time.Second)) + "," +
		strconv.FormatInt(s.expiry.Unix(), 10) + "," +
		s.deviceCode
}

// parseLoginState decodes a config state made by loginState.String.
//
// An interval which isn't positive is defaultPollInterval.
func parseLoginState(state string) (s loginState, err error) {
	// The device code goes last as only it might hold a comma
	fields := strings.SplitN(strings.TrimPrefix(state, pollState), ",", 3)
	if len(fields) != 3 || fields[2] == "" {
		// The state holds the device code so it isn't printed
		return s, errors.New("invalid login state: run the configuration again")
	}
	seconds, err := strconv.Atoi(fields[0])
	if err != nil {
		return s, fmt.Errorf("invalid login state interval: %w", err)
	}
	expiry, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return s, fmt.Errorf("invalid login state expiry: %w", err)
	}
	s.interval = time.Duration(seconds) * time.Second
	if s.interval <= 0 {
		s.interval = defaultPollInterval
	}
	s.expiry = time.Unix(expiry, 0)
	s.deviceCode = fields[2]
	return s, nil
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	passphrase := opt.KeyPassphrase
	if passphrase != "" {
		passphrase, err = obscure.Reveal(passphrase)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt key_passphrase: %w", err)
		}
	}

	url := baseURL(m)
	f := &Fs{
		name: name,
		root: strings.Trim(root, "/"),
		opt:  *opt,
	}
	f.conn, err = getConn(ctx, connKey{name: name, url: url, passphrase: passphrase}, func() (*vfs.FS, error) {
		return newVFS(ctx, name, url, passphrase, m)
	})
	if err != nil {
		return nil, err
	}
	f.vfs = f.conn.vfs
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		ReadMimeType:            true,
	}).Fill(ctx, f)

	// Check to see if the root is actually an existing file
	if space, filePath := f.split(""); space != "" && filePath != "/" {
		spaceID, err := f.spaceID(ctx, space)
		if err == nil {
			var node vfs.Node
			parent, leaf := vfs.SplitPath(filePath)
			node, err = f.vfs.Lookup(ctx, spaceID, parent, leaf)
			if err == nil && node.Type == vfs.TypeFile {
				f.root = path.Dir(f.root)
				// return an error with an fs which points to the parent
				return f, fs.ErrorIsFile
			}
		}
		if err != nil && !isNotFound(err) {
			_ = f.Shutdown(ctx)
			return nil, err
		}
	}
	return f, nil
}

// newVFS logs in to the API at url and unlocks the encryption key with
// passphrase, returning the file tree of the storage spaces of remote name.
func newVFS(ctx context.Context, name, url, passphrase string, m configmap.Mapper) (*vfs.FS, error) {
	ci := fs.GetConfig(ctx)
	// The login settings belong to the server and are not stored in the config.
	oidc, err := api.FetchOIDCConfig(ctx, url, fshttp.NewClient(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to read login config: %w", err)
	}
	_, ts, err := oauthutil.NewClient(ctx, name, m, &oauthutil.Config{
		ClientID:  oidc.ClientID,
		TokenURL:  oidc.TokenURL,
		Scopes:    oidc.Scopes,
		AuthStyle: oauth2.AuthStyleInParams,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure Retyc login: %w", err)
	}

	diagOnce.Do(func() { diag.SetOutput(diagWriter{}) })
	// The rclone transport applies the network flags and does the --dump
	// output, so the library's own dump is off and its insecure argument
	// has no effect.
	client := api.New(url, ci.UserAgent, ts, false, false, api.WithBaseTransport(fshttp.NewTransport(ctx)))

	// Unlocking the key with the passphrase is slow and memory hungry
	// (scrypt), so the unlocked key is kept in the session keyring where
	// there is one.
	identity, err := service.ResolveActiveUserIdentity(ctx,
		&retycconfig.Config{Keyring: retycconfig.KeyringConfig{Enabled: true, TTL: keyringTTL}},
		client,
		func() (string, error) {
			if passphrase == "" {
				return "", errors.New("key_passphrase is not set")
			}
			return passphrase, nil
		})
	if err != nil {
		return nil, fmt.Errorf("failed to unlock encryption key: %w", err)
	}

	return vfs.New(client, vfs.Options{
		NegativeTTL: vfs.DefaultNegativeTTL,
		// Uploads beyond this wait in Create, so allow as many as
		// rclone transfers files at once.
		UploadConcurrency: ci.Transfers,
		Identity:          identity,
		HideSymlinks:      true,
		Logf: func(format string, args ...any) {
			fs.Infof(name, format, args...)
		},
	}), nil
}

// isNotFound reports whether err says that a path names nothing
func isNotFound(err error) bool {
	return errors.Is(err, vfs.ErrNotExist) || errors.Is(err, vfs.ErrNotDir) || errors.Is(err, fs.ErrorDirNotFound)
}

// split returns the name of the storage space holding remote and the
// absolute path of remote inside it, "/" being the storage space itself.
//
// space is "" when remote is the root of the account.
func (f *Fs) split(remote string) (space, spacePath string) {
	space, spacePath = bucket.Split(bucket.Join(f.root, remote))
	return f.opt.Enc.FromStandardName(space), "/" + f.opt.Enc.FromStandardPath(spacePath)
}

// spaceID returns the ID of the storage space called space, or
// fs.ErrorDirNotFound.
func (f *Fs) spaceID(ctx context.Context, space string) (string, error) {
	id, err := f.vfs.DataroomByName(ctx, space)
	if errors.Is(err, vfs.ErrNotExist) {
		return "", fs.ErrorDirNotFound
	}
	return id, err
}

// lookup returns the node at spacePath, which must not be "/".
func (f *Fs) lookup(ctx context.Context, spaceID, spacePath string) (vfs.Node, error) {
	parent, leaf := vfs.SplitPath(spacePath)
	return f.vfs.Lookup(ctx, spaceID, parent, leaf)
}

// lookupDir checks that spacePath is a directory, returning
// fs.ErrorDirNotFound if it isn't.
func (f *Fs) lookupDir(ctx context.Context, spaceID, spacePath string) error {
	node, err := f.lookup(ctx, spaceID, spacePath)
	if isNotFound(err) || (err == nil && node.Type != vfs.TypeDir) {
		return fs.ErrorDirNotFound
	}
	return err
}

// mkdirAll makes the directory spacePath and its missing parents
func (f *Fs) mkdirAll(ctx context.Context, spaceID, spacePath string) error {
	if spacePath == "/" {
		return nil
	}
	node, err := f.lookup(ctx, spaceID, spacePath)
	if err == nil {
		if node.Type != vfs.TypeDir {
			return fs.ErrorIsFile
		}
		return nil
	}
	if !isNotFound(err) {
		return err
	}
	_, err = f.vfs.Mkdir(ctx, spaceID, spacePath)
	if errors.Is(err, vfs.ErrNotExist) {
		err = f.mkdirAll(ctx, spaceID, path.Dir(spacePath))
		if err != nil {
			return err
		}
		_, err = f.vfs.Mkdir(ctx, spaceID, spacePath)
	}
	if errors.Is(err, vfs.ErrExist) {
		// made by someone else in the meantime
		return nil
	}
	return err
}

// newObject makes an Object from a file node
func (f *Fs) newObject(remote, spaceID, spacePath string, node vfs.Node) *Object {
	return &Object{
		fs:      f,
		remote:  remote,
		spaceID: spaceID,
		path:    spacePath,
		node:    node,
	}
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("retyc root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision returns the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Microsecond
}

// Hashes returns the supported hash sets.
//
// The content is encrypted on the client so the API has no hash of it.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	space, spacePath := f.split(remote)
	if space == "" || spacePath == "/" {
		return nil, fs.ErrorObjectNotFound
	}
	spaceID, err := f.spaceID(ctx, space)
	if err == fs.ErrorDirNotFound {
		return nil, fs.ErrorObjectNotFound
	} else if err != nil {
		return nil, err
	}
	node, err := f.lookup(ctx, spaceID, spacePath)
	if isNotFound(err) {
		return nil, fs.ErrorObjectNotFound
	} else if err != nil {
		return nil, err
	}
	switch node.Type {
	case vfs.TypeFile:
		return f.newObject(remote, spaceID, spacePath, node), nil
	case vfs.TypeDir:
		return nil, fs.ErrorIsDir
	}
	return nil, fs.ErrorObjectNotFound
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	space, spacePath := f.split(dir)
	if space == "" {
		spaces, err := f.vfs.Datarooms(ctx)
		if err != nil {
			return nil, err
		}
		for _, space := range spaces {
			if space.DisplayName == "" {
				// A storage space without a name can't be given a path
				continue
			}
			d := fs.NewDir(f.opt.Enc.ToStandardName(space.DisplayName), time.Time{}).SetID(space.ID)
			entries = append(entries, d)
		}
		return entries, nil
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return nil, err
	}
	nodes, err := f.vfs.ReadDir(ctx, spaceID, spacePath)
	if isNotFound(err) {
		return nil, fs.ErrorDirNotFound
	} else if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(node.Name))
		switch node.Type {
		case vfs.TypeDir:
			entries = append(entries, fs.NewDir(remote, node.ModTime).SetID(node.ID))
		case vfs.TypeFile:
			entries = append(entries, f.newObject(remote, spaceID, path.Join(spacePath, node.Name), node))
		}
	}
	return entries, nil
}

// Put the object
//
// Copy the reader in to the new object which is returned.
//
// The new object may have been created if an error is returned
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: src.Remote(),
	}
	return o, o.Update(ctx, in, src, options...)
}

// Mkdir creates the directory if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	space, spacePath := f.split(dir)
	if space == "" {
		return nil
	}
	spaceID, err := f.spaceID(ctx, space)
	if err == fs.ErrorDirNotFound {
		return errCantCreateSpace
	} else if err != nil {
		return err
	}
	return f.mkdirAll(ctx, spaceID, spacePath)
}

// Rmdir deletes the directory
//
// Returns an error if it isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	space, spacePath := f.split(dir)
	if space == "" || spacePath == "/" {
		return errCantRemoveSpace
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return err
	}
	// Removing deletes whatever is at the path, so check it is a directory
	err = f.lookupDir(ctx, spaceID, spacePath)
	if err != nil {
		return err
	}
	err = f.vfs.Remove(ctx, spaceID, spacePath, false)
	switch {
	case errors.Is(err, vfs.ErrNotEmpty):
		return fs.ErrorDirectoryNotEmpty
	case isNotFound(err):
		return fs.ErrorDirNotFound
	}
	return err
}

// Purge deletes all the files in the directory
//
// Optional interface: Only implement this if you have a way of
// deleting all the files quicker than just running Remove() on the
// result of List()
func (f *Fs) Purge(ctx context.Context, dir string) error {
	space, spacePath := f.split(dir)
	if space == "" || spacePath == "/" {
		// Storage spaces can't be removed: let rclone empty it instead
		return fs.ErrorCantPurge
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return err
	}
	err = f.lookupDir(ctx, spaceID, spacePath)
	if err != nil {
		return err
	}
	err = f.vfs.Remove(ctx, spaceID, spacePath, true)
	if isNotFound(err) {
		return fs.ErrorDirNotFound
	}
	return err
}

// Copy src to this remote using server-side copy operations.
//
// This is stored with the remote path given.
//
// It returns the destination Object and a possible error.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}
	space, spacePath := f.split(remote)
	if space == "" || spacePath == "/" {
		return nil, fs.ErrorCantCopy
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return nil, err
	}
	if srcObj.fs.conn != f.conn || srcObj.spaceID != spaceID {
		// The API copies inside a storage space only, and only an Fs
		// sharing the connection sees the changes in its cache
		return nil, fs.ErrorCantCopy
	}
	node, _, err := f.vfs.Copy(ctx, spaceID, srcObj.path, spacePath, false)
	var copyErr *vfs.CopyError
	if errors.As(err, &copyErr) && copyErr.Step == vfs.CopyDestinationFolder && isNotFound(err) {
		err = f.mkdirAll(ctx, spaceID, path.Dir(spacePath))
		if err != nil {
			return nil, err
		}
		node, _, err = f.vfs.Copy(ctx, spaceID, srcObj.path, spacePath, false)
	}
	if errors.Is(err, vfs.ErrExist) {
		node, err = f.copyReplace(ctx, spaceID, srcObj.path, spacePath)
	}
	if errors.Is(err, vfs.ErrReplaceUnsupported) {
		return nil, fs.ErrorCantCopy
	} else if err != nil {
		return nil, retryErr(err)
	}
	return f.newObject(remote, spaceID, spacePath, node), nil
}

// copyReplace copies the file srcPath over the existing file dstPath.
//
// The API only copies to a new name, so the copy is made under a
// temporary name next to dstPath then renamed over it, which the API
// does atomically: dstPath is left as it was if anything fails.
func (f *Fs) copyReplace(ctx context.Context, spaceID, srcPath, dstPath string) (vfs.Node, error) {
	dir, leaf := vfs.SplitPath(dstPath)
	tmpPath := path.Join(dir, "."+leaf+"."+random.String(8)+".partial")
	node, _, err := f.vfs.Copy(ctx, spaceID, srcPath, tmpPath, false)
	if err != nil {
		return vfs.Node{}, err
	}
	err = f.vfs.Rename(ctx, spaceID, tmpPath, dstPath, true)
	if err != nil {
		if rmErr := f.vfs.Remove(ctx, spaceID, tmpPath, false); rmErr != nil {
			fs.Errorf(f, "Failed to remove temporary copy %q: %v", tmpPath, rmErr)
		}
		return vfs.Node{}, err
	}
	// Renaming keeps the node, only its name changes
	node.Name = leaf
	return node, nil
}

// retryErr marks err for the retries of rclone.
//
// A refusal which won't change by itself (storage exceeded, permission,
// login) is not retried. A server error (5xx), which the Retyc client
// doesn't replay itself, is retried.
func retryErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vfs.ErrStorageExceeded),
		errors.Is(err, vfs.ErrForbidden),
		errors.Is(err, vfs.ErrUnauthenticated):
		return fserrors.NoRetryError(err)
	}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status >= 500 && httpErr.Status <= 599 {
		return fserrors.RetryError(err)
	}
	return err
}

// Move src to this remote using server-side move operations.
//
// This is stored with the remote path given.
//
// It returns the destination Object and a possible error.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}
	space, spacePath := f.split(remote)
	if space == "" || spacePath == "/" {
		return nil, fs.ErrorCantMove
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return nil, err
	}
	if srcObj.fs.conn != f.conn || srcObj.spaceID != spaceID {
		// The API moves inside a storage space only, and only an Fs
		// sharing the connection sees the changes in its cache
		return nil, fs.ErrorCantMove
	}
	err = f.mkdirAll(ctx, spaceID, path.Dir(spacePath))
	if err != nil {
		return nil, err
	}
	// Replacing needs a recent API, so only ask for it when needed
	err = f.vfs.Rename(ctx, spaceID, srcObj.path, spacePath, false)
	if errors.Is(err, vfs.ErrExist) {
		err = f.vfs.Rename(ctx, spaceID, srcObj.path, spacePath, true)
	}
	if errors.Is(err, vfs.ErrReplaceUnsupported) {
		return nil, fs.ErrorCantMove
	} else if err != nil {
		return nil, err
	}
	return f.NewObject(ctx, remote)
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok || srcFs.conn != f.conn {
		// Only an Fs sharing the connection sees the changes in its cache
		fs.Debugf(src, "Can't move directory - not same remote")
		return fs.ErrorCantDirMove
	}
	srcSpace, srcPath := srcFs.split(srcRemote)
	dstSpace, dstPath := f.split(dstRemote)
	if srcSpace == "" || srcPath == "/" || dstSpace == "" || dstPath == "/" {
		// Storage spaces themselves can't be moved or created
		return fs.ErrorCantDirMove
	}
	srcID, err := srcFs.spaceID(ctx, srcSpace)
	if err != nil {
		return err
	}
	dstID, err := f.spaceID(ctx, dstSpace)
	if err == fs.ErrorDirNotFound {
		return fs.ErrorCantDirMove
	} else if err != nil {
		return err
	}
	if srcID != dstID {
		// The API moves inside a storage space only
		return fs.ErrorCantDirMove
	}
	_, err = f.lookup(ctx, dstID, dstPath)
	if err == nil {
		return fs.ErrorDirExists
	} else if !isNotFound(err) {
		return err
	}
	err = f.mkdirAll(ctx, dstID, path.Dir(dstPath))
	if err != nil {
		return err
	}
	err = f.vfs.Rename(ctx, dstID, srcPath, dstPath, false)
	switch {
	case errors.Is(err, vfs.ErrExist):
		return fs.ErrorDirExists
	case isNotFound(err):
		return fs.ErrorDirNotFound
	case err != nil:
		return err
	}
	return nil
}

// DirCacheFlush drops the cached listings and lookups of every storage space
// of the remote, and the list of storage spaces, so they are read again.
func (f *Fs) DirCacheFlush() {
	f.vfs.InvalidateAll()
}

// About gets quota information for the storage space of the root
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	space, _ := f.split("")
	if space == "" {
		return nil, errors.New("about needs the path of a storage space")
	}
	spaceID, err := f.spaceID(ctx, space)
	if err != nil {
		return nil, err
	}
	used, free, ok := f.vfs.Quota(ctx, spaceID)
	if !ok {
		return nil, errors.New("failed to read the usage of the storage space")
	}
	return &fs.Usage{
		Total: fs.NewUsageValue(used + free),
		Used:  fs.NewUsageValue(used),
		Free:  fs.NewUsageValue(free),
	}, nil
}

// Shutdown releases the connection of the Fs. The last Fs of the remote
// to do so stops the downloads in flight and releases the caches.
//
// Calls after the first do nothing.
func (f *Fs) Shutdown(ctx context.Context) (err error) {
	f.shutdown.Do(func() {
		err = f.conn.release()
	})
	return err
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// String returns a description of the Object
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns hash.ErrUnsupported as the API has no hash of the content
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.node.Size
}

// ModTime returns the modification time of the object
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.node.ModTime
}

// SetModTime sets the modification time of the object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	err := o.fs.vfs.SetModTime(ctx, o.spaceID, o.path, modTime)
	if err != nil {
		return err
	}
	o.node.ModTime = modTime
	return nil
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.node.ID
}

// MimeType of an Object if known, "" otherwise
func (o *Object) MimeType(ctx context.Context) string {
	return o.node.MIMEType
}

// fileReader reads a range of an open file
type fileReader struct {
	io.Reader
	file vfs.File
}

// Close stops the downloads of the file
func (r *fileReader) Close() error {
	return r.file.Close()
}

// readerAt reads a file at any offset, bounded by a context
type readerAt struct {
	ctx  context.Context
	file vfs.File
}

// ReadAt reads len(p) bytes of the file from off
func (r readerAt) ReadAt(p []byte, off int64) (int, error) {
	return r.file.ReadAtContext(r.ctx, p, off)
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(o.Size())
		default:
			if option.Mandatory() {
				fs.Logf(o, "Unsupported mandatory option: %v", option)
			}
		}
	}
	if limit < 0 || offset+limit > o.Size() {
		limit = max(o.Size()-offset, 0)
	}
	file, err := o.fs.vfs.Open(ctx, o.spaceID, o.node)
	if err != nil {
		return nil, retryErr(err)
	}
	return &fileReader{
		Reader: io.NewSectionReader(readerAt{ctx: ctx, file: file}, offset, limit),
		file:   file,
	}, nil
}

// readTracker notes whether its Reader was read from
type readTracker struct {
	io.Reader
	read bool
}

// Read reads from the Reader, noting that it did
func (r *readTracker) Read(p []byte) (int, error) {
	r.read = true
	return r.Reader.Read(p)
}

// Update the object with the contents of the io.Reader, modTime and size
//
// The new object may have been created if an error is returned
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	size := src.Size()
	if size < 0 {
		// The API needs the size of a file before its content
		return errUnknownSize
	}
	space, spacePath := o.fs.split(o.remote)
	if space == "" || spacePath == "/" {
		return errNoSpace
	}
	spaceID, err := o.fs.spaceID(ctx, space)
	if err != nil {
		return err
	}
	modTime := src.ModTime(ctx)
	tracker := &readTracker{Reader: in}
	node, err := o.fs.vfs.Create(ctx, spaceID, spacePath, size, modTime, tracker)
	// The parent is found missing before any of the content is read
	if err != nil && !tracker.read && errors.Is(err, vfs.ErrNotExist) {
		err = o.fs.mkdirAll(ctx, spaceID, path.Dir(spacePath))
		if err != nil {
			return err
		}
		node, err = o.fs.vfs.Create(ctx, spaceID, spacePath, size, modTime, tracker)
	}
	if err != nil {
		return retryErr(err)
	}
	if node.ModTime.IsZero() {
		node.ModTime = modTime
	}
	o.spaceID = spaceID
	o.path = spacePath
	o.node = node
	return nil
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	err := o.fs.vfs.Remove(ctx, o.spaceID, o.path, false)
	if isNotFound(err) {
		return fs.ErrorObjectNotFound
	}
	return err
}

// Check the interfaces are satisfied
var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.Purger          = (*Fs)(nil)
	_ fs.Copier          = (*Fs)(nil)
	_ fs.Mover           = (*Fs)(nil)
	_ fs.DirMover        = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Shutdowner      = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.MimeTyper       = (*Object)(nil)
)
