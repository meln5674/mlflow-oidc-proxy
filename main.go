package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/aquasecurity/yaml"
	flag "github.com/spf13/pflag"

	"github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
)

var (
	ConfigPath = flag.String("config", "./mlflow-oidc-proxy.cfg", "Path to YAML/JSON formatted configuration file")
)

func main() {
	flag.Parse()

	configFile, err := os.Open(*ConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	configBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := new(proxy.ProxyConfig).Init()

	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	err = config.ApplyDefaults()
	if err != nil {
		log.Fatal(err)
	}

	opts := proxy.ProxyOptions{
		Log: log.Default(),
	}

	proxy, err := proxy.NewProxy(*config, opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(proxy.ListenAndServe())
}
