package types

type StructPrep_t struct {
	TypeCascade bool
	VarName string
	TypeName string
}

type StructData_t struct {
	StructName string
	StructData []StructPrep_t
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