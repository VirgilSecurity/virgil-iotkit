package main

import (
	"./parser"
	"./template"
	"./types"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Settings
var (
	// Type for convert
	ConvertTypes                   = []string{"uint16_t", "uint32_t"}
	ConvertEncodeFuncPrefix        = "_encode"
	ConvertDecodeFuncPrefix        = "_decode"
	SkipMarker                     = "CODEGEN: SKIP"
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
func GetCascadeData(StructsList map[string]map[string]string, StructName string) (ConvertedStrings []types.StructPrep_t) {
	fmt.Printf("###=== SEARCH:[%s] \n", StructName)
	// Search strycture by name
	if StructData, ok := StructsList[StructName]; ok {
		for DataName, DataType := range StructData {
			// Check base types
			if parser.CheckEqualType(DataType, ConvertTypes)     {
				fmt.Printf("###===--- APPEND BASE[%s] <= BASE TYPE\n", DataName)
				ConvertedStrings = append(ConvertedStrings, types.StructPrep_t{false, DataName,DataType})
				continue
			}
			// Check cascade types
			TmpDataList := GetCascadeData(StructsList, DataType)
			if len(TmpDataList) > 0 {
					fmt.Printf("###===--- APPEND CASCADE [%s] <= CASCADE\n", DataName)
					ConvertedStrings = append(ConvertedStrings, types.StructPrep_t{true, DataName,DataType})
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
		TmpDt := GetCascadeData(StructsList, SrcStructName)
		if len(TmpDt) > 0 {
			StructData.StructName = ""
			StructData.StructData = nil
			FinData.StructsList = append(FinData.StructsList, types.StructData_t{StructName: SrcStructName, StructData: TmpDt})
		}
	}
	return
}

//********************************************************************************************************************
func fileCopy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	sz, err := io.Copy(destination, source)
	return sz, err
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

	// Create tmp directory
	dir, err := ioutil.TempDir("", "vs-codegen")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Preparing files to be processed
	preparedFiles := []string{}
	for _, FilePath := range InFiles {
		// Create temporary files
		dst := dir + "/" + filepath.Base(FilePath)
		_, err := fileCopy(FilePath, dst)
		if err != nil {
			log.Fatal(err)
		}

		// Replace typedefs
		parser.ReplaceTypedefs(dst, ConvertTypes)
		preparedFiles = append(preparedFiles, dst)
	}

	ParsedStructs = make(map[string]map[string]string)
	ParsedStructs, errret = parser.GetStructrures(preparedFiles, SkipMarker)
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
