# Apple T1 private NCM shim

Configuration 2 exposes the private CDC-NCM function on interfaces 4 and 5 but
omits an interrupt/status endpoint. Generic `cdc_ncm` requires that endpoint
under its default profile. This small adapter binds the mainline CDC-NCM and
USB-networking implementation with flags matching the T1 interface. It neither
switches USB configurations nor accesses SEP.
