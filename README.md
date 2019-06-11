
Features Included
-----------------
1) Intuitive: Interactive tool to access APIs https://haveibeenpwned.com/API/v2 
2) Extensibility and Resuability: Embeddable library in your code
3) User Friendly: Ouput can be saved in a CSV file or can be output to console as json string format
4) Security: The client connects to the server over https instead of using http and redirect. The server cert is present in the folder which is used to make https connections to server.

Requirements
------------
1) You would need golang compiler installed on your machine
2) Linux or MacOs enviornments
3) You could also use the uploaded binary(built on MacOS) to test.


How to use?
----------

NOTE: Add ca.cer file to the same location from where you invoke the tool.

Tool:
----
Check out the animated gif included to operate this tool.

Interative tool:
---------------
```
sindutrichyvijayakumar$ make tool
go run -v ./cmd/...
Interactive Shell For HaveIBeenPwned
>>> help
```

Commands:
---------
```
  breach               returns a single breach by breach name
                       Usage: breach <domain-name>
  breachedaccount      returns list of all breaches a particular account has been involved in
                       Usage: breachaccount <account>
  breaches             returns list of all breaches in the system
                       Usage: breaches
  clear                clear the screen
  dataclasses          returns all attributes of a record compromised in a breach
                       Usage: dataclasses
  exit                 exit the program
  help                 display help
  pasteaccount         returns all pastes for an account
                       Usage: pasteaccount <email-address>
  pwnedpassword        Check if a password is compromised or not
                       Usage: pwnedpassword 
 ```

Example Commands
----------------
```
>> breaches 
>> breach Adobe 
>> breachedaccount test@example.com
>> dataclasses
>> pasteaccount 
>> test@example.com
>> pwnedpassword
```


Output - The tool will ask you to specify if you want to save the output to csv or display on console.

Library
--------
You can get the output in form of string or json object. Each of the following functions return err, add error checks when you are using this module.

APIs for this module
-------------------
```
GetBreach(parameter, service, domain, truncateResponse, includeUnverified string) returns ([]BreachResp, string, error) returns a list of breaches for an account

GetSingleBreach(parameter, service, domain, truncateResponse, includeUnverified string)  returns (BreachResp, string, error)
returns list of all breaches a particular account has been involved in

GetDataClasses(parameter, service, domain string) returns ([]string, string, error) 
returns data classes

GetPasteAccount(parameter, service, domain string) returns ([]PasteResp, string, error) 
returns all pastes for an account

IsPasswordCompromised(password string) - returns (bool, error) 
checks if password is compromised or not
```
