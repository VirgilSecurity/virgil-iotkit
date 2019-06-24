package main

import (
	"./parser"
	"./template"
	"./types"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
)

// Settings
var (
	// Type for convert
	ConvertTypes                   = []string{"uint16_t", "uint32_t"}
	ConvertEncodeFuncPrefix        = "_encode"
	ConvertDecodeFuncPrefix        = "_decode"
	H_Template              string = "conv_h.tmpl"
	C_Template              string = "conv_c.tmpl"
)

var (
	FinStructsData types.Structs_t
)

// For files parameter
type TypeInFiles []string

//********************************************************************************************************************
// For multiple argv key
func (i *TypeInFiles) String() string {
	return fmt.Sprint(*i)
}

//********************************************************************************************************************
// For multiple argv key
func (i *TypeInFiles) Set(value string) error {
	*i = append(*i, value)
	return nil
}

//********************************************************************************************************************
func CreateFile(FileName string) *os.File {
	if FileName == "" {
		os.Exit(1)
	}
	NewFile, err := os.Create(FileName)
	if err != nil {
		os.Exit(1)
	}
	return NewFile
}

//********************************************************************************************************************
func GetCascadeData(StructsList map[string]map[string]string, StructName string, Prefix string) (ConvertedStrings []string) {
	fmt.Printf("###=== SEARCH:[%s] PREFIX:[%s]\n", StructName, Prefix)
	// Search strycture by name
	if StructData, ok := StructsList[StructName]; ok {
		for DataType, DataName := range StructData {
			// Check base types
			if parser.CheckEqualType(DataType, ConvertTypes) {
				fmt.Printf("###===--- APPEND BASE[%s] <= BASE TYPE\n", Prefix+DataName)
				ConvertedStrings = append(ConvertedStrings, Prefix+DataName)
				continue
			}
			// Check cascade types
			TmpDataList := GetCascadeData(StructsList, DataType, Prefix+DataName+".")
			if len(TmpDataList) > 0 {
				for _, TmpData := range TmpDataList {
					fmt.Printf("###===--- APPEND CASCADE [%s] <= CASCADE\n", TmpData)
					ConvertedStrings = append(ConvertedStrings, TmpData)
				}
			}
		}
	}
	return ConvertedStrings
}

//********************************************************************************************************************
func CreateFinalData(StructsList map[string]map[string]string) (FinData types.Structs_t) {
	var StructData types.StructData_t

	fmt.Print("### PREPARING FINAL DATA \n")
	for SrcStructName, _ := range StructsList {
		fmt.Printf("###=== Struct: [%s]\n", SrcStructName)
		TmpDt := GetCascadeData(StructsList, SrcStructName, "")
		if len(TmpDt) > 0 {
			StructData.StructName = ""
			StructData.StructData = nil
			FinData.StructsList = append(FinData.StructsList, types.StructData_t{StructName: SrcStructName, StructData: TmpDt})
		}
	}
	return
}

//********************************************************************************************************************
func main() {
	var (
		errret error = nil
		//		CTemplate *template.Template
		//		HTemplate *template.Template
		InFiles       TypeInFiles
		ParsedStructs map[string]map[string]string
	)

	// Program argv
	flag.Var(&InFiles, "i", "Input Structs file")
	TmplDirectory := flag.String("d", "", "Template directory")
	OutputHFileName := flag.String("oh", "vs_conv.h", "Output H file")
	OutputCFileName := flag.String("oc", "vs_conv.c", "Output C file")
	flag.Parse()

	//Preparing file paths
	for _, FilePath := range InFiles {
		FilePath = path.Base(FilePath)
	}

	ParsedStructs = make(map[string]map[string]string)
	ParsedStructs, errret = parser.GetStructrures(InFiles)
	if errret != nil {
		fmt.Printf("ERROR reading Structs [%s]\n", errret)
		os.Exit(1)
	}

	FinStructsData = CreateFinalData(ParsedStructs)
	if len(FinStructsData.StructsList) < 1 {
		fmt.Println("STRUCTS FOR CONVERTINF NOT FOUND")
		os.Exit(1)
	}
	FinStructsData.DstHFile = path.Base(*OutputHFileName)
	FinStructsData.DstCFile = path.Base(*OutputCFileName)
	FinStructsData.EncPref = ConvertEncodeFuncPrefix
	FinStructsData.DecPref = ConvertDecodeFuncPrefix
	FinStructsData.HeaderTag = strings.Replace(FinStructsData.DstHFile, ".","_",-1)

	fmt.Print("### EXECUTE TEMPLATE \n")
	HTemplate, CTemplate, errret := template.PrepareTemplates(path.Join(*TmplDirectory, H_Template), path.Join(*TmplDirectory, C_Template))
	if errret != nil {
		os.Exit(1)
	}

	errret = template.ExecTemplate(FinStructsData, HTemplate, CTemplate, *OutputHFileName, *OutputCFileName)
	if errret != nil {
		os.Exit(1)
	}

	fmt.Println("ALL OPERATION FINISH")
}
