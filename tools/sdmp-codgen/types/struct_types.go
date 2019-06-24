package types

type StructData_t struct {
	StructName string
	StructData []string
}

type Structs_t struct {
	StructsList []StructData_t
	EncPref     string
	DecPref     string
	SrcHeader   string
	HeaderTag   string
	DstCFile    string
	DstHFile    string
}