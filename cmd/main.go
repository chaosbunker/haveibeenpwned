package main

import (
	//	"fmt"
	"github.com/abiosoft/ishell"
	"github.com/sinduvi87/haveibeenpwned/pwned"
	"strings"
)

func main() {
	// create new shell.
	// by default, new shell includes 'exit', 'help' and 'clear' commands.
	shell := ishell.New()
	// display welcome info.
	shell.Println("Interactive Shell For HaveIBeenPwned")

	// register a function command.
	shell.AddCmd(&ishell.Cmd{
		Name: "breachedaccount",
		Help: "returns list of all breaches a particular account has been involved in \n\t\t\t  Usage: breachaccount <account>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("breachedaccount takes one attribute which is an email address")
				return
			}
			var filename string
			c.Println("Filter breaches against a domain? If yes enter domain name otherwise press enter")
			domain := c.ReadLine()
			c.Println("Truncate response ? y/n")
			truncate := c.ReadLine()
			c.Println("Include unverified breaches ? y/n")
			unverified := c.ReadLine()
			c.Println("Save output to a CSV file ? y/n")
			com := c.ReadLine()
			if "Y" == strings.ToUpper(com) {
				c.Println("Specify the name of the file you want to save the output to")
				filename = c.ReadLine()
				if filename == "" {
					c.Println("Not a valid filename, result will be displayed on console")
				}
			}
			if "Y" == strings.ToUpper(truncate) {
				truncate = "true"
			}
			if "Y" == strings.ToUpper(unverified) {
				unverified = "true"
			}
			jsondata, result, e := pwned.GetBreach(c.Args[0], "breachedaccount/", domain, truncate, unverified)
			if e != nil {
				c.Println(e)
			} else if len(filename) != 0 {
				e := WriteBreachData(filename, jsondata)
				if e != nil {
					c.Printf("Error while writing to file %v", e)
					c.Println(result)
				} else {
					c.Println("Written succesfully to " + filename)
				}
			} else {
				c.Println(result)
			}

		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "breaches",
		Help: "returns list of all breaches in the system \n\t\t\t  Usage: breaches",
		Func: func(c *ishell.Context) {
			if len(c.Args) > 0 {
				c.Println("breaches takes no attribute")
				return
			}
			var filename string
			c.Println("Filter breaches against a domain? If yes enter domain name otherwise press enter")
			domain := c.ReadLine()
			c.Println("Save output to a CSV file ? y/n")
			com := c.ReadLine()
			if "Y" == strings.ToUpper(com) {
				c.Println("Specify the name of the file you want to save the output to")
				filename = c.ReadLine()
				if filename == "" {
					c.Println("Not a valid filename, result will be displayed on console")
				}
			}
			jsondata, result, e := pwned.GetBreach("", "breaches/", domain, "false", "false")
			if e != nil {
				c.Println(e)
			} else if len(filename) != 0 {
				e := WriteBreachData(filename, jsondata)
				if e != nil {
					c.Printf("Error while writing to file %v", e)
					c.Println(result)
				} else {
					c.Println("Written succesfully to " + filename)
				}
			} else {
				c.Println(result)
			}

		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "breach",
		Help: "returns a single breach by breach name \n\t\t\t  Usage: breach <domain-name>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("breach takes one attribute which is a domain name")
				return
			}
			var filename string
			c.Println("Save output to a CSV file ? y/n")
			com := c.ReadLine()
			if "Y" == strings.ToUpper(com) {
				c.Println("Specify the name of the file you want to save the output to")
				filename = c.ReadLine()
				if filename == "" {
					c.Println("Not a valid filename, result will be displayed on console")
				}
			}
			jsondata, result, e := pwned.GetSingleBreach("", "breach/", c.Args[0], "false", "false")
			if e != nil {
				c.Println(e)
			} else if len(filename) != 0 {
				var jsdata []pwned.BreachResp
				jsdata = append(jsdata, jsondata)
				e := WriteBreachData(filename, jsdata)
				if e != nil {
					c.Printf("Error while writing to file %v", e)
					c.Println(result)
				} else {
					c.Println("Written succesfully to " + filename)
				}
			} else {
				c.Println(result)
			}
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "dataclasses",
		Help: "returns all attributes of a record compromised in a breach\n\t\t\t  Usage: dataclasses",
		Func: func(c *ishell.Context) {
			if len(c.Args) > 0 {
				c.Println("dataclasses does not take any parameters, just enter dataclasses")
				return
			}
			var filename string
			c.Println("Save output to a CSV file ? y/n")
			com := c.ReadLine()
			if "Y" == strings.ToUpper(com) {
				c.Println("Specify the name of the file you want to save the output to")
				filename = c.ReadLine()
				if filename == "" {
					c.Println("Not a valid filename, result will be displayed on console")
				}
			}
			jsondata, result, e := pwned.GetDataClasses("", "dataclasses/", "")
			if e != nil {
				c.Println(e)
			} else if len(filename) != 0 {
				e := WriteDataClasses(filename, jsondata)
				if e != nil {
					c.Printf("Error while writing to file %v", e)
					c.Println(result)
				} else {
					c.Println("Written succesfully to " + filename)
				}
			} else {
				c.Println(result)
			}

		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "pasteaccount",
		Help: "returns all pastes for an account\n\t\t\t  Usage: pasteaccount <email-address>",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("pasteaccount takes one attribute which is an email address")
				return
			}
			var filename string
			c.Println("Save output to a CSV file ? y/n")
			com := c.ReadLine()
			if "Y" == strings.ToUpper(com) {
				c.Println("Specify the name of the file you want to save the output to")
				filename = c.ReadLine()
				if filename == "" {
					c.Println("Not a valid filename, result will be displayed on console")
				}
			}

			jsondata, result, e := pwned.GetPasteAccount(c.Args[0], "pasteaccount/", "")
			if e != nil {
				c.Println(e)
			} else if len(filename) != 0 {
				e := WritePasteData(filename, jsondata)
				if e != nil {
					c.Printf("Error while writing to file %v", e)
					c.Println(result)
				} else {
					c.Println("Written succesfully to " + filename)
				}
			} else {
				c.Println(result)
			}
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "pwnedpassword",
		Help: "Check if a password is compromised or not\n\t\t\t  Usage: pwnedpassword",
		Func: func(c *ishell.Context) {
			c.Println("Enter password you would like to check")
			password := c.ReadPassword()
			result, e := pwned.IsPasswordCompromised(password)
			if e != nil {
				c.Println(e)
			} else {
				if result {
					c.Println("Password is compromised. Use 1password or LastPass for password generation")
				} else {
					c.Println("Good Job in selecting password")
				}
			}
		},
	})
	// run shell
	shell.Run()
}
