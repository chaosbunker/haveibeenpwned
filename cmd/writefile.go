package main

import (
	"encoding/csv"
	"github.com/sinduvi87/haveibeenpwned/pwned"
	"os"
	"strconv"
	"strings"
)

func WriteDataClasses(filename string, jsondata []string) error {
	csvdatafile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer csvdatafile.Close()

	writer := csv.NewWriter(csvdatafile)

	for _, dc := range jsondata {
		var record []string

		record = append(record, dc)
		writer.Write(record)
	}
	writer.Flush()
	return nil
}

func WritePasteData(filename string, jsondata []pwned.PasteResp) error {
	csvdatafile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer csvdatafile.Close()

	writer := csv.NewWriter(csvdatafile)
	var r []string
	r = append(r, "Source", "Id", "Title", "Date", "EmailCount")
	writer.Write(r)
	for _, p := range jsondata {
		var record []string
		record = append(record, p.Source, p.Id, p.Title, p.Date, strconv.Itoa(p.EmailCount))
		writer.Write(record)
	}
	return nil
}

func WriteBreachData(filename string, jsondata []pwned.BreachResp) error {
	csvdatafile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer csvdatafile.Close()

	writer := csv.NewWriter(csvdatafile)
	var r []string
	r = append(r, "Name", "Title", "Domain", "BreachDate", "AddedDate",
		"ModifiedDate", "PwnCount", "Description", "LogoPath",
		"DataClasses", "IsVerified", "IsFabricated", "IsSensitive",
		"IsRetired", "IsSpamList")
	writer.Write(r)
	for _, b := range jsondata {
		var record []string
		ds := strings.Join(b.DataClasses, ",")
		record = append(record, b.Name, b.Title, b.Domain, b.BreachDate, b.AddedDate,
			b.ModifiedDate, strconv.Itoa(b.PwnCount), b.Description, b.LogoPath,
			ds, strconv.FormatBool(b.IsVerified), strconv.FormatBool(b.IsFabricated), strconv.FormatBool(b.IsSensitive),
			strconv.FormatBool(b.IsRetired), strconv.FormatBool(b.IsSpamList))
		writer.Write(record)
	}
	writer.Flush()
	return nil
}
