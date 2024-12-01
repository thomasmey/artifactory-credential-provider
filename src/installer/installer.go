package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	kcv1 "k8s.io/kubelet/config/v1"
)

func main() {
	var cfgFilePath = flag.String("config-file", "/cfg/credential-provider.yaml", "Path to config yaml")
	var execProviderPath = flag.String("provider-exec", "/bin/artifactory-credential-provider", "Path to provider executable")
	var hostFsPath = flag.String("hostfs", "/host", "Path to hostfs mount")
	flag.Parse()

	log.Print("Install Mode - Try to install to node")
	install(*cfgFilePath, *execProviderPath, *hostFsPath)
}

func install(cfgFilePath, execProviderPath, hostFsPath string) {

	imageCredOptions := []string{"--image-credential-provider-config", "--image-credential-provider-bin-dir"}

	foundOptions := make(map[string]string)
	var kubeletPid int

	procDir := filepath.Join(hostFsPath, "/proc")
	entries, err := os.ReadDir(procDir)
	if err != nil {
		log.Fatalf("Error reading /proc directory: %v", err)
	}

	numRegex := regexp.MustCompile(`^\d+$`)
	log.Print("Try to find kubelet PID")
	for _, entry := range entries {
		if entry.IsDir() && numRegex.MatchString(entry.Name()) {
			fp := filepath.Join(procDir, entry.Name(), "cmdline")
			cmdline, err := ioutil.ReadFile(fp)
			if err != nil {
				log.Printf("Error reading file: %v", err)
				return
			}

			ca := strings.Split(string(cmdline), "\x00")

			if len(ca) == 0 || !strings.HasSuffix(ca[0], "kubelet") {
				continue
			}
			kubeletPid, _ = strconv.Atoi(entry.Name())

			for _, str := range ca {
				for _, imageCredOption := range imageCredOptions {
					if strings.HasPrefix(str, imageCredOption) {
						key, value, found := strings.Cut(str, "=")
						if found {
							k := strings.TrimPrefix(key, "--")
							foundOptions[k] = value
						}
					}
				}
			}
			break
		}
	}

	if kubeletPid == 0 {
		log.Fatalf("Node doesn't run kubelet! Aborting installation")
	}
	log.Print("Found kubelet PID ", kubeletPid)

	// read and parse the config to add
	cfgDataAdd, err := ioutil.ReadFile(cfgFilePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	var cfgMetaAdd metav1.TypeMeta
	yaml.Unmarshal(cfgDataAdd, &cfgMetaAdd)

	if cfgMetaAdd.Kind != "CredentialProviderConfig" {
		log.Fatal("Unsupported config type: ", cfgMetaAdd.Kind)
	}
	var cfgAdd kcv1.CredentialProviderConfig

	switch cfgMetaAdd.APIVersion {
	case kcv1.SchemeGroupVersion.String():
		yaml.Unmarshal(cfgDataAdd, &cfgAdd)
	}

	// does the cmdline alreay contain both imageCredOptions?
	if len(foundOptions) == len(imageCredOptions) {
		// read config file and add our config
		cfgFile := filepath.Join(hostFsPath, foundOptions["image-credential-provider-config"])
		binDir := filepath.Join(hostFsPath, foundOptions["image-credential-provider-bin-dir"])
		cfgData, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		var cfgMeta metav1.TypeMeta
		yaml.Unmarshal(cfgData, &cfgMeta)

		if cfgMeta.Kind != "CredentialProviderConfig" {
			log.Fatal("Unsupported config type:", cfgMeta.Kind)
		}

		switch cfgMeta.APIVersion {
		case kcv1.SchemeGroupVersion.String():
			var cfg kcv1.CredentialProviderConfig
			yaml.Unmarshal(cfgData, &cfg)

			found := false
			for i := 0; i < len(cfg.Providers); i++ {
				if cfg.Providers[i].Name == cfgAdd.Providers[0].Name {
					// replace existing config with same name
					cfg.Providers[i] = cfgAdd.Providers[0]
					found = true
					log.Print("Did modify existing image credential provider config for ", cfg.Providers[i].Name)
					break
				}
			}

			if !found {
				cfg.Providers = append(cfg.Providers, cfgAdd.Providers[0])
			}

			// write new config
			cfgNew, _ := yaml.Marshal(cfg)
			err := os.WriteFile(cfgFile, cfgNew, 0)
			if err != nil {
				log.Fatal(err)
			}
			log.Print("image credential provider config file was updated ", cfgFile)
		default:
			log.Fatal("Unsupported config version:", cfgMeta.APIVersion)
		}

		// copy executable into imageCredBinDir
		exec := filepath.Base(execProviderPath)
		dstPath := filepath.Join(binDir, exec)
		log.Printf("Installing executable from %s to %s\n", execProviderPath, dstPath)
		err = copyFile(execProviderPath, dstPath)
		if err != nil {
			log.Fatal(err)
		}

		log.Print("Going to restart kubelet")
		process, _ := os.FindProcess(kubeletPid)
		process.Signal(syscall.SIGTERM)
		log.Print("Installation done")
		return
	}

	log.Fatal("kubelet runs without image-credential-provider cmdline arguments, unsupported install mode!")
	// create config&bin dir
	// create config in imageCredConfDir
	// copy executable into imageCredBinDir
	// findout systemd unit from PID
	// we only support systemd systems!
	// create systemd kubelet.service overlay
	// systemctl daemon-reload
	// systemctl restart kubelet.service
}

func copyFile(srcPath, dstPath string) error {
	// Open the source file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("could not open source file: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("could not create destination file: %v", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("error copying file: %v", err)
	}

	err = dstFile.Sync()
	if err != nil {
		return fmt.Errorf("error syncing destination file: %v", err)
	}

	return nil
}
