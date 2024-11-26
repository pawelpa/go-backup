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
	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Srcdir  Source   `toml:"source"`
	Dstdir  LocalDst `toml:"local"`
	Servers map[string]DestinationHost
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
	Passpharse  string
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
	return errors.New("host not found in known_hosts file")
}

func FileExists(file string) bool {

	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func (c *Config) ParseConfig(configFile string) error {

	if !FileExists(configFile) {
		return errors.New("config file doesn't exsists on given path")
	}

	_, err := toml.DecodeFile(configFile, c)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) ComposeLocalFile(tempFile string) string {

	return fmt.Sprintf("%s/%s", c.Dstdir.Dstdir, filepath.Base(tempFile))

}

func CreateTemporaryFile() (string, error) {

	dir, err := os.MkdirTemp("", "go-backup")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/backup_%s.tar.gz", dir, time.Now().Format("20060102150405")), nil

}

func ComposeBackupChecksumFileName(fileToChecksum string) string {
	return fmt.Sprintf("%s.%s", fileToChecksum, "sha256sum")
}

func (c *Config) GetRemotePath(host string) string {
	return c.Servers[host].DstPath
}

func (c *Config) GetSourceDirs() []string {
	return c.Srcdir.Srcdirs
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

func (c *Config) GetPrivateKeyPasspharse(host string) string {
	return c.Servers[host].Passpharse
}

func (c *Config) sendFileToHost(filePath string, host string) error {

	var auth goph.Auth
	var err error
	port := c.GetPort(host)
	username := c.GetUserName(host)
	ip := c.GetHost(host)

	if c.GetUseKey(host) {

		auth, err = goph.Key(c.GetPrivKeyPath(host), c.GetPrivateKeyPasspharse(host))
		if err != nil {
			return err
		}

	} else {

		auth = goph.Password(c.GetPassword(host))

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

	remoteFile := c.ComposeRemoteFilePath(filePath, host)

	err = sftpClient.MkdirAll(c.GetRemotePath(host))

	if err != nil {
		return err
	}

	err = sftpClient.Chmod(c.GetRemotePath(host), 0700)

	if err != nil {
		return err
	}

	err = client.Upload(filePath, remoteFile)

	if err != nil {
		return err
	}

	err = sftpClient.Chmod(remoteFile, 0600)

	if err != nil {
		return err
	}

	return nil
}

func (c *Config) ComposeRemoteFilePath(localFileName string, host string) string {

	return fmt.Sprintf("%s/%s", c.Servers[host].DstPath, filepath.Base(localFileName))
}

func IsBaseDirExists(file string) error {

	baseDir := path.Dir(file)
	info, err := os.Stat(baseDir)
	if err == nil && info.IsDir() {
		return nil
	}
	return os.MkdirAll(baseDir, 0700)

}

func CopyFile(inFile, outFile string) error {

	if err := IsBaseDirExists(outFile); err != nil {
		return err
	}

	in, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	bytesCopied, err := io.Copy(out, in)

	if err != nil {
		return err
	}

	inFileStat, err := in.Stat()
	if err != nil {
		return err
	}

	if bytesCopied != inFileStat.Size() {
		return errors.New("not all bytes copied")
	}

	return nil
}

func CopyFilesFromTempToLocalBackup(tempFile, checksumFile string, c *Config) error {

	if err := CopyFile(tempFile, c.ComposeLocalFile(tempFile)); err != nil {
		return err
	}

	if err := CopyFile(checksumFile, c.ComposeLocalFile(checksumFile)); err != nil {
		return err
	}
	return nil

}

func verifyChecksum(file string) error {

	var verifyOut bytes.Buffer

	cmd := exec.Command("sha256sum", "-c", ComposeBackupChecksumFileName(file))

	cmd.Stdout = &verifyOut

	cmd.Dir = filepath.Dir(file)

	if err := cmd.Run(); err != nil {
		return err
	}

	re, err := regexp.Compile(".*:.[OK|DOBRZE]")

	if err != nil {
		return err
	}

	if re.Match(verifyOut.Bytes()) {
		return nil
	}
	return errors.New("checksum incorrect")
}

func generateChecksumForFile(file string) error {

	cmd := exec.Command("sha256sum", filepath.Base(file))

	checksumFile, err := os.Create(ComposeBackupChecksumFileName(file))

	if err != nil {
		return err
	}

	defer checksumFile.Close()

	cmd.Dir = filepath.Dir(file)

	cmd.Stdout = checksumFile

	if err = cmd.Run(); err != nil {
		return err
	}

	return nil

}

func main() {

	var config Config

	configPath := flag.String("config", "config.toml", "Configuration file path")

	flag.Parse()

	if err := config.ParseConfig(*configPath); err != nil {
		log.Fatal(err)
	}

	tempFile, err := CreateTemporaryFile()
	if err != nil {
		log.Fatal("Can't create temporary file: ", err)
	}
	defer os.RemoveAll(filepath.Dir(tempFile))

	tarFile, err := os.Create(tempFile)

	if err != nil {
		log.Fatal("Main create backup file: ", err)
	}

	gzipWriter := gzip.NewWriter(tarFile)
	tarWriter := tar.NewWriter(gzipWriter)

	walkFunc := func(file string, finfo os.FileInfo, err error) error {

		var link string

		if err != nil {
			return err
		}

		if finfo.Mode()&os.ModeSymlink == os.ModeSymlink {
			if link, err = os.Readlink(file); err != nil {
				return err
			}
		}

		hdr, err := tar.FileInfoHeader(finfo, link)

		if err != nil {
			log.Fatal("walkFunc: ", err)
		}

		if filepath.IsAbs(file) {

			hdr.Name = file
		}

		tarWriter.WriteHeader(hdr)

		if !finfo.Mode().IsRegular() {
			return nil
		}
		if finfo.Mode().IsDir() {
			return nil
		}

		srcFile, err := os.Open(file)

		if err != nil {
			log.Fatal("walkFunc ", err)
		}
		defer srcFile.Close()

		//Copy content of file to tar
		_, err = io.Copy(tarWriter, srcFile)

		if err != nil {
			log.Fatal("walkFunc", err)
		}

		return nil
	}

	dirs := config.GetSourceDirs()

	for _, dir := range dirs {

		if !FileExists(dir) {
			log.Printf("Source directory %s doesn't exist, skipping...", dir)
			continue
		}

		if err := filepath.Walk(dir, walkFunc); err != nil {

			fmt.Printf("Failed to create backup file: %s", err)

		}
	}
	tarWriter.Close()
	gzipWriter.Close()

	err = generateChecksumForFile(tempFile)

	if err != nil {
		log.Println("Can't generete checksum file: ", err)
	}

	err = verifyChecksum(tempFile)

	if err != nil {

		log.Println("Checksum verification failed: ", err)

	}

	//copy backup file to local destination directory if exists

	if err = CopyFilesFromTempToLocalBackup(tempFile, ComposeBackupChecksumFileName(tempFile), &config); err != nil {
		log.Println("Can't create local backup. Skipping...", err)
	}

	//send backup to remote hosts
	for host := range config.Servers {

		if err = config.sendFileToHost(tempFile, host); err != nil {

			log.Fatal("Error sending backup to remote host: ", err)

		}

		//send checksum to remote hosts
		if err = config.sendFileToHost(ComposeBackupChecksumFileName(tempFile), host); err != nil {

			log.Fatal("Error sending checksum file to remote host", err)
		}
	}

	log.Println("Backup done.")
}
