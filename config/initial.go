package config

import (
	"fmt"
	"os"

	"github.com/metacubex/mihomo/common/guard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Init prepare necessary files
func Init(dir string) error {
	// mod: unified disk/network guard, see common/guard. Never create the home
	// directory or a placeholder config file in deny mode.
	if !guard.DiskAllowed() {
		guard.Refuse("disk", "creating configuration directory "+dir)
		return guard.ErrDisabled
	}
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	return nil
}
