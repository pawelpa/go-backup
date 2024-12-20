package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

type App struct {
	config           Config
	tempBackupFile   string
	tempChecksumFile string
	encryptedFile    string
	fileNameFormat   string
	tarFile          *os.File
	gzipWr           *gzip.Writer
	tarWr            *tar.Writer
	multiWr          io.Writer
	logfile          *os.File
}

type Config struct {
	EncOpt  Encrypt  `toml:"encryption"`
	LogOpt  Log      `toml:"log"`
	GzipOpt Gzip     `toml:"gzip"`
	Srcdir  Source   `toml:"source"`
	Dstdir  LocalDst `toml:"local"`
	Servers map[string]DestinationHost
}

type Encrypt struct {
	Enabled    bool
	PubKeyPath string
}

type Log struct {
	Logfile string
	Append  bool
}

type Gzip struct {
	CompressionLevel int
}

type LocalDst struct {
	Dstdir string
}
type Source struct {
	Srcdirs []string
}

type DestinationHost struct {
	Host        string
	Port        uint
	DstPath     string
	PrivKeyPath string
	Username    string
	Password    string
	UseKey      bool
	Passphrase  string
}

func (app *App) Init(configPath string) error {

	app.fileNameFormat = "2006-01-02_150405"

	if err := app.config.ParseConfig(configPath); err != nil {
		return fmt.Errorf("can't parse config file: %s", err)
	}

	if app.checkIfLoggingIsEnabled() {
		if app.checkIfPathIsValid() {
			var err error
			flags := os.O_CREATE | os.O_WRONLY

			if app.config.LogOpt.Append {
				flags |= os.O_APPEND
			} else {
				flags |= os.O_TRUNC
			}
			app.logfile, err = os.OpenFile(app.config.LogOpt.Logfile, flags, 0600)

			if err != nil {
				return fmt.Errorf("can't setup logging to file: %s", err)
			}

			app.multiWr = io.MultiWriter(os.Stdout, app.logfile)
			log.SetOutput(app.multiWr)
		} else {
			return fmt.Errorf("invalid logfile path in configuration file")
		}
	}

	if !app.doSourceDirectoriesExist() {
		return fmt.Errorf("source directories do not exist, backup aborted")
	}

	dir, err := app.CreateTemporaryDirectory()

	if err != nil {
		return fmt.Errorf("can't create temporary directory for backup: %s", err)
	}

	app.tempBackupFile = fmt.Sprintf("%s/backup_%s.tar.gz", dir, time.Now().Format(app.fileNameFormat))
	app.tempChecksumFile = fmt.Sprintf("%s.sha256sum", app.tempBackupFile)
	app.encryptedFile = fmt.Sprintf("%s.enc", app.tempBackupFile)

	app.prepareTarFile()

	app.gzipWr, err = gzip.NewWriterLevel(app.tarFile, int(app.config.GzipOpt.CompressionLevel))

	if err != nil {
		return fmt.Errorf("can't setup gzip writer: %s", err)
	}

	app.tarWr = tar.NewWriter(app.gzipWr)

	return nil
}

func (app *App) doSourceDirectoriesExist() bool {

	srcDirs := app.GetSourceDirs()

	for _, srcDir := range srcDirs {
		if FileExists(srcDir) {
			return true
		}
	}
	return false
}

func (app *App) CloseWriters() {

	app.tarWr.Close()
	app.gzipWr.Close()
	app.tarFile.Close()

}

func (app *App) checkIfLoggingIsEnabled() bool {

	return app.config.LogOpt.Logfile != ""

}

func (app *App) checkIfPathIsValid() bool {

	regex := regexp.MustCompile(`^/[a-zA-Z0-9._/\\-]*$`)

	return regex.MatchString(app.config.LogOpt.Logfile)
}

func (app *App) getTempFile() string {
	return app.tempBackupFile
}
func (app *App) getChecksumFile() string {
	return app.tempChecksumFile
}
func (app *App) getEncryptedFile() string {
	return app.encryptedFile
}

func (app *App) Finish() {

	defer app.logfile.Close()
	defer os.RemoveAll(path.Dir(app.tempBackupFile))

}

func (app *App) isEncryptionEnabled() bool {

	return app.config.EncOpt.Enabled
}

func (app *App) GetSourceDirs() []string {

	return app.config.Srcdir.Srcdirs
}

func (app *App) CreateTemporaryDirectory() (string, error) {

	dir, err := os.MkdirTemp("", "go-backup-")
	if err != nil {
		return "", err
	}

	return dir, nil

}

func verifyHost(host string, remote net.Addr, key ssh.PublicKey) error {

	hostFound, err := goph.CheckKnownHost(host, remote, key, "")

	if hostFound && err != nil {
		return err
	}
	if hostFound && err == nil {
		return nil
	}
	//if host not found create one in known_host file
	// return goph.AddKnownHost(host, remote, key, "")

	//if host not found in known_hosts file show error
	return fmt.Errorf("host %s not found in known_host file", host)
}

func FileExists(file string) bool {

	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func (c *Config) ParseConfig(configFile string) error {

	if !FileExists(configFile) {
		return errors.New("config file doesn't exist on given path")
	}

	_, err := toml.DecodeFile(configFile, c)

	if err != nil {
		return err
	}
	return nil
}

func (app *App) composeLocalFile(tempFile string) string {
	return fmt.Sprintf("%s/%s", app.config.Dstdir.Dstdir, path.Base(tempFile))
}

func (c *Config) GetPubKeyPath() string {
	return c.EncOpt.PubKeyPath
}

func (c *Config) GetRemotePath(host string) string {
	return c.Servers[host].DstPath
}

func (c *Config) GetPassword(host string) string {
	return c.Servers[host].Password
}

func (c *Config) GetUserName(host string) string {
	return c.Servers[host].Username
}

func (c *Config) GetHost(host string) string {
	return c.Servers[host].Host
}

func (c *Config) GetUseKey(host string) bool {
	return c.Servers[host].UseKey
}

func (c *Config) GetPort(host string) uint {
	return c.Servers[host].Port
}

func (c *Config) GetPrivKeyPath(host string) string {
	return c.Servers[host].PrivKeyPath
}

func (c *Config) GetPrivateKeyPassphrase(host string) string {
	return c.Servers[host].Passphrase
}

func (app *App) createRemoteBackup() error {

	c := app.config

	log.Printf("Remote backup started.")

	for currentHost := range c.Servers {

		var auth goph.Auth
		var err error

		port := c.GetPort(currentHost)
		username := c.GetUserName(currentHost)
		ip := c.GetHost(currentHost)

		log.Printf("Sending backup to: %s...", ip)

		if c.GetUseKey(currentHost) {

			auth, err = goph.Key(c.GetPrivKeyPath(currentHost), c.GetPrivateKeyPassphrase(currentHost))

			if err != nil {
				return err
			}

			log.Printf("Authenticate using public key.")

		} else {

			auth = goph.Password(c.GetPassword(currentHost))

			log.Printf("Authenticate using password.")
		}

		client, err := goph.NewConn(&goph.Config{
			User:     username,
			Addr:     ip,
			Port:     port,
			Auth:     auth,
			Callback: verifyHost,
		})

		if err != nil {
			return err
		}

		sftpClient, err := client.NewSftp()

		if err != nil {
			return err
		}

		defer client.Close()

		remoteDir := app.getRemoteDestinationDirectory(currentHost)

		remoteBackupFile := path.Join(remoteDir, path.Base(app.getTempFile()))

		remoteChecksumFile := path.Join(remoteDir, path.Base(app.getChecksumFile()))

		remoteEncryptedFile := path.Join(remoteDir, path.Base(app.getEncryptedFile()))

		err = sftpClient.MkdirAll(remoteDir)

		if err != nil {
			return fmt.Errorf("mkdir %s failed: %s", remoteDir, err)
		}

		err = sftpClient.Chmod(remoteDir, 0700)

		if err != nil {
			return fmt.Errorf("chmod remote directory failed: %s", err)
		}

		err = client.Upload(app.getTempFile(), remoteBackupFile)

		if err != nil {
			return fmt.Errorf("uploading %s to %s filed: %s", app.getTempFile(), remoteDir, err)
		}

		err = sftpClient.Chmod(remoteBackupFile, 0600)

		if err != nil {
			return fmt.Errorf("chmod %s error: %s", remoteBackupFile, err)
		}

		err = client.Upload(app.tempChecksumFile, remoteChecksumFile)

		if err != nil {
			return fmt.Errorf("error uploading %s to %s: %s", app.tempChecksumFile, remoteChecksumFile, err)
		}

		err = sftpClient.Chmod(remoteChecksumFile, 0600)

		if err != nil {
			return fmt.Errorf("chmod %s error: %s", remoteChecksumFile, err)
		}

		if app.isEncryptionEnabled() {

			err = client.Upload(app.getEncryptedFile(), remoteEncryptedFile)

			if err != nil {
				return fmt.Errorf("error uploading %s to %s: %s", app.getEncryptedFile(), remoteEncryptedFile, err)
			}

			err = sftpClient.Chmod(remoteEncryptedFile, 0600)

			if err != nil {
				return fmt.Errorf("chmod %s error: %s", remoteEncryptedFile, err)
			}

		}

	}
	log.Printf("Remote backup done.")
	return nil
}

func (app *App) getRemoteDestinationDirectory(currentHost string) string {

	return app.config.Servers[currentHost].DstPath

}

func createBaseDirIfNotExists(file string) error {

	baseDir := path.Dir(file)
	info, err := os.Stat(baseDir)
	if err == nil && info.IsDir() {
		return nil
	}
	return os.MkdirAll(baseDir, 0700)

}

func CopyFile(inFile, outFile string) error {

	if err := createBaseDirIfNotExists(outFile); err != nil {
		return err
	}

	in, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("can't open %s: %s", inFile, err)
	}
	defer in.Close()

	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("can't open %s: %s", outFile, err)
	}
	defer out.Close()

	bytesCopied, err := io.Copy(out, in)

	if err != nil {
		return err
	}

	inFileStat, err := in.Stat()
	if err != nil {
		return fmt.Errorf("can't stat file %s: %s", inFile, err)
	}

	if bytesCopied != inFileStat.Size() {
		return fmt.Errorf("error copying from source to destination file: %s", err)
	}

	return nil
}
func (app *App) LoadPubKey() (string, error) {

	pubkeypath := app.config.GetPubKeyPath()

	pubkey, err := os.ReadFile(pubkeypath)

	if err != nil {
		return "", err
	}

	return string(pubkey[:]), nil
}

func (app *App) LoadBackupFile() ([]byte, error) {

	return os.ReadFile(app.getTempFile())

}

func (app *App) WriteEncryptedFile(data []byte) error {

	encryptedFile, err := os.OpenFile(app.getEncryptedFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)

	if err != nil {
		return fmt.Errorf("can't create encrypted file, %s", err)
	}
	defer encryptedFile.Close()

	_, err = encryptedFile.Write(data)

	if err != nil {
		return fmt.Errorf("can't write to encrypted file, %s", err)
	}

	return nil
}

func (app *App) encryptBackup() error {

	pubkey, err := app.LoadPubKey()

	if err != nil {
		return fmt.Errorf("can't open pubkey file for encryption  %s", err)
	}

	publicKey, err := crypto.NewKeyFromArmored(pubkey)

	if err != nil {
		return fmt.Errorf("can't read armored pubkey, %s", err)
	}

	pgp := crypto.PGP()

	encHandle, err := pgp.Encryption().Recipient(publicKey).New()

	if err != nil {
		return fmt.Errorf("error creating encryption handle, %s", err)
	}

	data, err := app.LoadBackupFile()

	if err != nil {
		return fmt.Errorf("can't load backup file for encryption, %s", err)
	}

	encFile, err := encHandle.Encrypt(data)

	if err != nil {
		return fmt.Errorf("error encrypting data, %s", err)
	}

	err = app.WriteEncryptedFile(encFile.Bytes())

	if err != nil {
		return fmt.Errorf("%s", err)
	}

	return nil

}

func (app *App) createLocalBackup() error {

	if err := CopyFile(app.getTempFile(), app.composeLocalFile(app.getTempFile())); err != nil {
		return err
	}

	if err := CopyFile(app.getChecksumFile(), app.composeLocalFile(app.getChecksumFile())); err != nil {
		return err
	}

	if app.isEncryptionEnabled() {

		if err := CopyFile(app.getEncryptedFile(), app.composeLocalFile(app.getEncryptedFile())); err != nil {
			return err
		}
	}

	log.Printf("Local backup created.")
	return nil

}

func (app *App) verifyChecksum() error {

	var verifyOut bytes.Buffer

	cmd := exec.Command("sha256sum", "-c", app.getChecksumFile())

	cmd.Stdout = &verifyOut
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "LANG=C")

	cmd.Dir = filepath.Dir(app.getChecksumFile())

	if err := cmd.Run(); err != nil {
		return err
	}

	re, err := regexp.Compile(".*:.[OK]")

	if err != nil {
		return err
	}

	if re.Match(verifyOut.Bytes()) {
		log.Printf("Archive checksum verified")
		return nil
	}
	return errors.New("checksum incorrect")
}

func (app *App) generateChecksumFile() error {

	file := app.getTempFile()

	cmd := exec.Command("sha256sum", path.Base(file))

	checksumFile, err := os.Create(app.getChecksumFile())

	if err != nil {
		return err
	}

	defer checksumFile.Close()

	cmd.Dir = path.Dir(file)

	cmd.Stdout = checksumFile

	if err = cmd.Run(); err != nil {
		return err
	}
	log.Printf("Checksum file generated.")
	return nil

}

func (app *App) prepareTarFile() {

	var err error

	app.tarFile, err = os.Create(app.getTempFile())

	if err != nil {
		log.Fatal("error creating tar file: ", err)
	}

}

func (app *App) generateGzipArchive() {

	var walkFunction = func(path string, finfo os.FileInfo, err error) error {

		var link string

		if err != nil {
			return err
		}

		if finfo.Mode()&os.ModeSymlink == os.ModeSymlink {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}

		hdr, err := tar.FileInfoHeader(finfo, link)

		if err != nil {
			log.Fatalf("can't populate header: %s", err)
			return err
		}

		if filepath.IsAbs(path) {

			hdr.Name = path
		}

		err = app.tarWr.WriteHeader(hdr)
		if err != nil {
			log.Fatalf("can't write header info: %s", err)
			return err
		}

		if !finfo.Mode().IsRegular() {
			return nil
		}
		if finfo.Mode().IsDir() {
			return nil
		}

		srcFile, err := os.Open(path)

		if err != nil {
			log.Fatalf("can't open source file %s for reading: %s", path, err)
		}
		defer srcFile.Close()

		_, err = io.Copy(app.tarWr, srcFile)

		if err != nil {
			log.Fatalf("can't copy file %s to archive: %s", path, err)
		}

		return nil
	}

	srcPaths := app.GetSourceDirs()

	log.Printf("generating archive...")

	for _, srcPath := range srcPaths {

		log.Printf("Adding %s to archive.", srcPath)

		if !FileExists(srcPath) {

			log.Printf("Source directory %s doesn't exist, skipping...", srcPath)

		} else {

			if err := filepath.Walk(srcPath, walkFunction); err != nil {
				log.Printf("failed to create backup file: %s\n", err)
			}

		}
	}
	app.CloseWriters()
}

func main() {

	var app App

	configPath := flag.String("config", "config.toml", "Configuration file path")

	flag.Parse()

	err := app.Init(*configPath)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Backup started.")

	app.generateGzipArchive()

	err = app.generateChecksumFile()

	if err != nil {
		log.Println("can't generate checksum file: ", err)
	}

	err = app.verifyChecksum()

	if err != nil {

		log.Println("Checksum verification failed: ", err)

	}

	if app.isEncryptionEnabled() {

		if err = app.encryptBackup(); err != nil {
			log.Println("Can't encrypt backup, ", err)
		}
	}

	if err = app.createLocalBackup(); err != nil {
		log.Println("Can't create local backup. Skipping...", err)
	}

	err = app.createRemoteBackup()

	if err != nil {
		log.Printf("Error sending files to remote host: %s", err)
	}

	log.Println("Backup done.")

	app.Finish()

}
