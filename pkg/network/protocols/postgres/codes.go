package postgres

const (
	ParseTag byte = 'P'
	QueryTag byte = 'Q'
	BindTag  byte = 'B'

	// this is not a postgres code. we add it to uniform the startup message with the others
	StartupTag byte = '+'
	// this happens only when for some reason in ebpf we cannot read the fragment and we return all 0
	EmptyTag byte = 0
)
