package config

import (
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v3"

	"github.com/13excite/xdp-fw-demo/pkg/internal/log"
)

const (
	// a program name used in version and logging
	// strings, also used as UA identification plus
	// version (if any set)
	ProgramName = "xdpfw"

	// default configuration file if no any file
	// specified; if the default file does not exist
	// we fall back to the embedded default configuration
	DefaultConfigFile string = "/etc/xdpfw/xdpfw.yaml"

	// default addr for the http api
	DefaultListenAddr = "[::1]:5055"
)

type TGlobal struct {

	// options set by configuration (from file or default)
	Opts *TConfig

	// runtime settings set after configuration
	// is parsed
	Runtime *TRuntime

	L *log.Logger
}

func (c *TGlobal) O() *TConfig {
	return c.Opts
}

type TConfig struct {
	// logging config
	Log TLogConfig `json:"log" yaml:"log"`

	// controller configuration
	Controller TControllerConfig `json:"controller" yaml:"controller"`

	// plugins configuration, keyed by type then by name
	Plugins map[string]map[string]TPluginConfig `json:"plugins" yaml:"plugins"`
}

type TLogConfig struct {
	Format  string `json:"format" yaml:"format"`
	Log     string `json:"log" yaml:"log"`
	Level   string `json:"level" yaml:"level"`
	Verbose bool   `json:"verbose" yaml:"verbose"`

	// max log size in MB
	MaxSize int `json:"max-size" yaml:"max-size"`
	// max log file count
	MaxBackups int `json:"max-backups" yaml:"max-backups"`
	// maximum number of days to retain old log files
	MaxAge int `json:"max-age" yaml:"max-age"`
	// if the rotated log files should be compressed using gzip
	Compression bool `json:"compression" yaml:"compression"`
}

type TRuntime struct {
	Version string `json:"version" yaml:"version"`
	Date    string `json:"date" yaml:"date"`

	ProgramName string `json:"program-name" yaml:"program-name"`
	Hostname    string `json:"hostname" yaml:"hostname"`
}

func (t *TRuntime) GetUseragent() string {
	return fmt.Sprintf("%s/%s", ProgramName, t.Version)
}

type TControllerConfig struct {
	// common API requests (all plugins register
	// their methods on the shared group)
	API TAPIOptions `json:"api" yaml:"api"`
}

type TAPIOptions struct {
	// listen options in form "[::1]:5055"
	Listen string `json:"listen" yaml:"listen"`

	// debug for echo server
	Debug bool `json:"debug" yaml:"debug"`
}

type TPluginConfig interface{}

// a default fallback configuration if no config options
// are set and no file is provided or detected
var DefaultConfig = []byte(`
# default configuration

log:
  # logging format could be "string" or "json"
  format: "string"

  # "stdout" - output to console or a log path like
  # "/var/log/xdpfw/xdpfw.log"
  log: "stdout"

  # level of debugging could be "debug", "info"; could be
  # overridden by a command line switch
  level: "debug"

controller:
  api:
    listen: "[::1]:5055"
    debug: false

plugins:
  monitoring:
    metrics:
      enabled: true
  bpf:
    firewall:
      enabled: true
      options:
        interface: "lo"
`)

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// NewConfig loads configuration from a file, from the default
// file path, or from the embedded default configuration.
func NewConfig(filename string, Log *log.Logger) (*TConfig, error) {
	id := "(config) (yaml)"

	var err error
	var conf TConfig
	var content []byte

	// explicit configuration file: read it and fail on error
	if len(filename) > 0 {
		if content, err = os.ReadFile(filename); err != nil {
			if Log != nil {
				Log.Errorf("%s error reading config file:'%s', err:'%s'",
					id, filename, err)
			}
			return &conf, err
		}
	}

	if len(filename) == 0 {
		config := DefaultConfigFile
		if Exists(config) {
			if content, err = os.ReadFile(config); err != nil {
				if Log != nil {
					Log.Errorf("%s error reading config file:'%s', err:'%s'",
						id, config, err)
				}
				return &conf, err
			}
		} else {
			content = DefaultConfig
		}
	}

	if err = yaml.Unmarshal(content, &conf); err != nil {
		if Log != nil {
			Log.Errorf("%s error parsing config data err:'%s'", id, err)
		}
		return &conf, err
	}

	file := filename
	if len(file) == 0 {
		file = "default"
	}
	if Log != nil {
		Log.Debugf("%s successfully loaded configuration from:'%s'", id, file)
	}

	return &conf, err
}

func (c *TGlobal) CreateLogger(opts *log.LoggerOptions) (*log.Logger, error) {

	var err error
	var l *log.Logger

	options := log.LoggerOptions{
		Debug:  log.DefaultLoggingDebug,
		Stdout: log.DefaultLoggingStdout,
		Path:   log.DefaultLoggingPath,
	}

	if opts != nil {
		options.Debug = opts.Debug
		options.Stdout = opts.Stdout

		if opts.Path != "stdout" {
			options.Path = opts.Path
		}

		options.Verbose = opts.Verbose

		options.MaxAge = opts.MaxAge
		options.MaxSize = opts.MaxSize
		options.MaxBackups = opts.MaxBackups
		options.Compression = opts.Compression
	}

	if l, err = log.CreateLogger(options); err != nil {
		fmt.Printf("error creating default logger, err:'%s'", err)
		return l, err
	}

	return l, err
}

func (t *TConfig) GetListenAddr() string {
	addr := DefaultListenAddr
	options := t.Controller.API
	if len(options.Listen) > 0 {
		addr = options.Listen
	}
	return addr
}

func StringInSlice(key string, list []string) bool {
	for _, entry := range list {
		if entry == key {
			return true
		}
	}
	return false
}
