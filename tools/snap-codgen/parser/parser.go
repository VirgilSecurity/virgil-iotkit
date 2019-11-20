package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

//********************************************************************************************************************
func CheckEqualType(StructDataType string, DataTypes []string) bool {
	for _, DataType := range DataTypes {
		if strings.Contains(StructDataType, DataType) {
			return true
		}
	}
	return false
}

//********************************************************************************************************************
func GetStructrures(InputFiles []string, SkipMarker string) (AllStructs map[string]map[string]string, errret error) {

	var RLine string
	var StructType string
	var StructData map[string]string

	AllStructs = make(map[string]map[string]string)

	// While on file list
	fmt.Print("### PARSING FILES \n")
	for _, InputFileName := range InputFiles {

		// Open file and reader
		fmt.Printf("###=== Opening input file [%s]\n", InputFileName)
		InFile, err := os.Open(InputFileName)
		if err != nil {
			errret = errors.New(fmt.Sprintf("[GetStructrures]: Error opening File [%s]", InputFileName))
			return AllStructs, errret
		}
		FileReader := bufio.NewReader(InFile)
		if FileReader == nil {
			errret = errors.New(fmt.Sprintf("[GetStructrures]: Error opening Reader for File [%s]", InputFileName))
			return AllStructs, errret
		}

		//Parsing file
		fmt.Printf("###===--- Parsing file \n")
		for {
			RLine, err = FileReader.ReadString('\n')
			if err == io.EOF {
				break
			}
			// Search structure contains ("typedef", "__packed__")
			if strings.Contains(RLine, "typedef") && strings.Contains(RLine, "__packed__") {
				if !strings.Contains(RLine, "{") { // If "{" not fount on line read string to "{" symbol
					if _, err = FileReader.ReadString('{'); err == io.EOF {
						break
					}
				}

				// Clear temporary map
				StructType = ""
				StructData = make(map[string]string)

				// Read the body structure to "}"
				RLine, err = FileReader.ReadString('}') // reading body structure
				if err == io.EOF {
					break
				}

				// Parse struct data lines and fill struct data array
				BodyReader := bufio.NewScanner(strings.NewReader(strings.TrimRight(strings.TrimLeft(RLine, " "), "}")))
				for BodyReader.Scan() {

					FieldsStructLine := strings.SplitN(strings.TrimLeft(strings.TrimRight(BodyReader.Text(), ";"), " "), " ", 3)
					if len(FieldsStructLine) > 1 {
					    FieldsStructLine[1] = strings.TrimRight(FieldsStructLine[1], ";")
						fmt.Printf("###===------TYPE: [%s] NAME:[%s]\n", FieldsStructLine[0], FieldsStructLine[1])
						if len(FieldsStructLine) > 2 && strings.Contains(FieldsStructLine[2], SkipMarker) {
						    fmt.Printf("^^^ SKIP\n")
                            continue
                        }
						StructData[FieldsStructLine[1]] = FieldsStructLine[0]
					}
				}

				fmt.Println("=== STR NAME ===")
				fmt.Println(StructData)
				fmt.Println("=== END STR NAME ===")

				// Reading Struct Name
				RLine, err = FileReader.ReadString(';') // reading struct name
				if err == io.EOF {
					break
				}

				//Append data to final structure
				StructType = strings.TrimRight(strings.TrimLeft(RLine, " "), ";")
				if len(StructType) > 0 {
					AllStructs[StructType] = StructData
					fmt.Printf("###===--- FOUND [%s]\n", StructType)
				}
			}
		}
	} // End of while on file list

	// If Structs not found (reset final data)
	if len(AllStructs) < 1 {
		AllStructs = nil
		errret = errors.New(fmt.Sprintf("Structs not found"))
		return AllStructs, errret
	}

	return AllStructs, errret
}

//********************************************************************************************************************
func ReplaceTypedefs(InputFileName string, DataTypes []string) (errret error) {

	// Open file and reader
	fmt.Printf("###=== Opening input file [%s]\n", InputFileName)
	InFile, err := os.Open(InputFileName)
	if err != nil {
		errret := errors.New(fmt.Sprintf("[GetStructrures]: Error opening File [%s]", InputFileName))
		return errret
	}

	FileReader := bufio.NewReader(InFile)
	if FileReader == nil {
		errret = errors.New(fmt.Sprintf("[GetStructrures]: Error opening Reader for File [%s]", InputFileName))
		return errret
	}

	//Parsing file
	fmt.Printf("###===--- Parsing file \n")
	for {
		RLine, err := FileReader.ReadString('\n')
		if err == io.EOF {
			break
		}
		// Search structure contains ("typedef", "__packed__")
		if strings.Contains(RLine, "typedef") && CheckEqualType(RLine, DataTypes) {

			input, err := ioutil.ReadFile(InputFileName)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			for _, DataType := range DataTypes {
				if strings.Contains(RLine, DataType) {

					parts := strings.Split(RLine, " ")
					typeName := strings.Replace(parts[2], ";", "", -1)
					typeName = strings.Replace(typeName, "\n", "", -1)

					output := bytes.Replace(input, []byte(typeName), []byte(DataType), -1)
					if err = ioutil.WriteFile(InputFileName, output, 0666); err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				}
			}

		}
	}

	return nil
}
