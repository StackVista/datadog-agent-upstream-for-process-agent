package postgres

const (
	ParseTag byte = 'P'
	QueryTag byte = 'Q'
	BindTag  byte = 'B'

	// these are not postgres codes. we add them to uniform the startup message with the others
	StartupTag     byte = '+'
	TerminationTag byte = '='
	// this happens only when for some reason in ebpf we cannot read the fragment and we return all 0
	EmptyTag byte = 0
)
