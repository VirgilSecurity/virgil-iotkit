package template

import (
	"../types"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"
)

//********************************************************************************************************************
func PrepareTemplates(HTemplateFile string, CTemplateFile string) (HTemplate *template.Template, CTemplate *template.Template, errret error) {
	var (
		CTemplateStr string
		HTemplateStr string
		TmpBytes []byte
	)
	fmt.Print("=== Preparing template\n")

	TmpBytes,errret = ioutil.ReadFile(HTemplateFile)
	HTemplateStr = string(TmpBytes)
	if errret != nil {
		fmt.Printf("Error open template [%s]\n",HTemplateFile)
		return
	}

	TmpBytes,errret = ioutil.ReadFile(CTemplateFile)
	CTemplateStr = string(TmpBytes)
	if errret != nil {
		fmt.Printf("Error open template [%s]\n",CTemplateFile)
		return
	}

	fmt.Printf("===--- Parsing [%s]\n", HTemplateFile)
	HTemplate, errret = template.New("HTemplateStr").Parse(HTemplateStr)
	if errret != nil {
		fmt.Printf("Error parsing [%s] \n [%v]\n",HTemplateFile,errret)
		return
	}

	fmt.Printf("===--- Parsing [%s]\n", CTemplateFile)
	CTemplate, errret = template.New("CTemplateStr").Parse(CTemplateStr)
	if errret != nil {
		fmt.Printf("Error parsing [%s] \n [%v]\n",CTemplateFile,errret)
		return
	}

	return
}
//********************************************************************************************************************
func ExecTemplate(FinStructsData types.Structs_t,HTemplate *template.Template, CTemplate *template.Template, OutputHFileName  string, OutputCFileName  string) (errret error) {
	errret = nil

	fmt.Print("=== Creating output files\n")

	FinStructsData.HeaderTag = strings.ToUpper(strings.Replace(path.Base(OutputHFileName),".","_", -1))

	HFileHandler, errret:= os.Create(OutputHFileName)
	if errret != nil {
		fmt.Printf("Error create file [%s]\n [%s]\n", OutputHFileName, errret)
	}
	fmt.Printf("===--- [%s] \n",OutputHFileName)
	errret = HTemplate.Execute(HFileHandler, FinStructsData)
	if errret != nil {
		fmt.Printf("Error execute template [%s]\n [%s]\n",HTemplate.Name(),errret)
		return errret
	}
	_ = HFileHandler.Close()

	CFileHandler, errret:= os.Create(OutputCFileName)
	if errret != nil {
		fmt.Printf("Error create file [%s]\n [%s]\n", OutputHFileName, errret)
	}
	fmt.Printf("===--- [%s] \n",OutputCFileName)
	errret = CTemplate.Execute(CFileHandler, FinStructsData)
	if errret != nil {
		fmt.Printf("Error execute template [%s]\n [%s]\n",CTemplate.Name(),errret)
		return errret
	}
	_ = CFileHandler.Close()

	return errret
}
