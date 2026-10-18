package cli

import (
	"github.com/metacubex/mihomo/common/structure"
)

// decoder returns the weakly typed decoder used for listener fragments, the
// same one the regular listener parser uses.
func decoder() *structure.Decoder {
	return structure.NewDecoder(structure.Option{
		TagName:          "inbound",
		WeaklyTypedInput: true,
		KeyReplacer:      structure.DefaultKeyReplacer,
	})
}

// proxyDecoder returns the weakly typed decoder used for proxy fragments, the
// same one the regular proxy parser uses.
func proxyDecoder() *structure.Decoder {
	return structure.NewDecoder(structure.Option{
		TagName:          "proxy",
		WeaklyTypedInput: true,
		KeyReplacer:      structure.DefaultKeyReplacer,
	})
}
