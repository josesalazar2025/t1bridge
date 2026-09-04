# T1 configuration selector

`t1_cfgsel` is registered as a USB device driver before the internal iBridge
enumerates. It matches only Apple `05ac:8600`, then selects a configuration only
when one descriptor set uniquely contains the expected T1 display, CDC-NCM,
and SEP interfaces and bulk endpoints. Missing, altered, or ambiguous
descriptors return `-ENODEV`; the driver does not guess a configuration number.

The implementation follows the configuration-selector structure used by the
mainline `rtl8152` driver but was written independently. It does not contain
code from the earlier research selector.
