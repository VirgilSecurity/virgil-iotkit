//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package initializer

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
)

const BACKUP_FILE_SUFFIX = ".bak"

type PersistenceManager struct {
	FileName             string
}

func (p PersistenceManager) Persist(data string) error {
	if err := p.createFileIfNotExists(); err != nil {
		return err
	}
	// Create backup file
	if err := p.createBackupFile(); err != nil {
		return err
	}

	// Append line to file
	if err := p.appendLine(data); err != nil {
		return err
	}

	return nil
}

func (p PersistenceManager) createBackupFile() error {
	destinationFile := p.FileName + BACKUP_FILE_SUFFIX

	// Remove previous backup file if exists
	var _, stat = os.Stat(destinationFile)
	if os.IsExist(stat) {
		if err := os.Remove(destinationFile); err != nil {
			return fmt.Errorf("failed to remove backup file: %s", err)
		}
	}

	// Create backup file
	input, err := ioutil.ReadFile(p.FileName)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(destinationFile, input, os.ModeAppend | 0644)
	if err != nil {
		return err
	}

	return nil
}

func (p PersistenceManager) createFileIfNotExists() error {
	var _, stat = os.Stat(p.FileName)
	if os.IsNotExist(stat) {
		var file, err = os.Create(p.FileName)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	return nil
}


func (p PersistenceManager) appendLine(line string) error {
	fileHandle, _ := os.OpenFile(p.FileName, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	writer := bufio.NewWriter(fileHandle)
	defer fileHandle.Close()

	if _, err := fmt.Fprintln(writer, line); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}
