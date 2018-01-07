/*
 * File: ndefence.go
 *
 * Description: Primary code for the ndefence binary.
 *
 * Author: Robert Bisewski <contact@ibiscybernetics.com>
 */

//
// Package
//
package main

//
// Imports
//
import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"./ndefenceHostname"
	"./ndefenceIO"
	"./ndefenceUtils"
)

//
// Globals
//
var (

	// Current location of the log directory.
	logDirectory = "/var/log/"

	// Name of the access and error log files
	accessLog = "access.log"
	errorLog  = "error.log"

	// Web location
	webLocation = "/var/www/html/data/"

	// Name of the IP log file on the webserver.
	ipLog = "ip.log"

	// Name of the whois log file on the webserver.
	whoisLog = "whois.log"

	// Name of the redirect log file on the webserver.
	redirectLog = "redirect.log"

	// Name of the blocked log file on the webserver.
	blockedLog = "blocked.log"

	// Parameter for the server type
	serverType = ""

	// Valid server types
	validServerTypes = []string{"apache", "nginx"}

	// Path to default site config
	defaultSiteConfigPath = ""

	// Boolean to flag whether a given server is valid or not
	serverIsValid = false

	// Whether or not to print the current version of the program
	printVersion = false

	// default version value
	Version = "0.0"

	// Argument for enabling daemon mode
	daemonMode = false
)

// Initialize the argument input flags.
func init() {

	// Server type flag
	flag.StringVar(&serverType, "server-type", "nginx",
		"Currently active server; e.g. 'nginx' ")

	// Daemon mode flag
	flag.BoolVar(&daemonMode, "daemon-mode", false,
		"Whether or not to run this program as a background service.")

	// Version mode flag
	flag.BoolVar(&printVersion, "version", false,
		"Print the current version of this program and exit.")
}

//
// PROGRAM MAIN
//
func main() {

	// String variable to hold eventual output, as well error variable.
	var err error

	// Variables to hold the extracted IP addresses and to hold ip
	// addresses to consider blocking, if enough data is gathered
	var ipAddresses = make(map[string]int)
	var blockedIPAddresses = []string{}

	// Variable to hold a generic log header format
	var logHeaderFmt = "Generated on: %s\n\nLog Data for %s\n" +
		"-------------------------\n\n"

	// Parse the flags, if any.
	flag.Parse()

	// if requested, go ahead and print the version; afterwards exit the
	// program, since this is all done
	if printVersion {
		fmt.Println("ndefence v" + Version)
		os.Exit(0)
	}

	// Lower case the serverType variable value.
	serverType = strings.ToLower(serverType)

	// Print the usage message if not nginx or apache.
	for _, t := range validServerTypes {

		// check if a given server is valid or not
		if t == serverType {
			serverIsValid = true
			break
		}
	}

	// Print the usage message if the server is an unknown type.
	if !serverIsValid {
		flag.Usage()
		os.Exit(1)
	}

	// Check if the web data directory actually exists.
	_, err = ioutil.ReadDir(webLocation)

	// ensure no error occurred
	if err != nil {
		fmt.Println("The following directory does not exist: ",
			webLocation)
		os.Exit(1)
	}

	// Assemble the access.log file location.
	accessLogLocation := logDirectory + serverType + "/" + accessLog

	// main infinite loop...
	for {

		// Attempt to break up the file into an array of strings a demarked by
		// the newline character.
		lines, err := ndefenceIO.TokenizeFile(accessLogLocation, "\n")

		// if an error occurred, print it out and terminate the program
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}

		// determine the last valid line
		lastLineNum := len(lines) - 2

		// safety check, ensure the value is at least zero
		if lastLineNum < 0 {
			lastLineNum = 0
		}

		// obtain the contents of the last line
		lastLine := lines[lastLineNum]

		// extract the date of the last line, this is so that the program can
		// gather data concerning only the latest entries
		latestDateInLog, err := ndefenceIO.ObtainLatestDate(lastLine)

		// check if an error occurred
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// attempt to grab the current day/month/year
		datetime := time.Now().Format(time.UnixDate)

		//
		// safety check, ensure this actually got a meaningful string
		//
		// * should be at least len("DD/MM/YYYY"), so at least 10
		//
		if len(datetime) < 10 {
			fmt.Println("Warning: Improper system date-time value" +
				"detected!\n")
			os.Exit(1)
		}

		// assemble the generic log header used by all of the logs
		genericLogHeader := fmt.Sprintf(logHeaderFmt, datetime,
			latestDateInLog)

		// set the title and append the header to the redirectLogContents
		redirectLogContents := "Redirection Entry Data\n\n"
		redirectLogContents += genericLogHeader

		// compile a regex to search for 302 found-redirections
		redirectCapture := "\" 302 [0-9]{1,15} \"(.{2,64})\" "
		redirectRegex := regexp.MustCompile(redirectCapture)

		// turn the latest data string into a regex
		re := regexp.MustCompile(latestDateInLog)

		// for every line...
		linesAddedToRedirect := 0
		for _, line := range lines {

			// verify that a match could be found
			verify := re.FindString(line)

			// skip a line if the entry is not the latest date
			if len(verify) < 1 {
				continue
			}

			// attempt to split that line via spaces
			elements := strings.Split(line, " ")

			// safety check, ensure that element actually has a length
			// of at least 1
			if len(elements) < 1 {
				continue
			}

			// grab the first element, that is the IP address
			ip := elements[0]

			// determine if this is a valid IPv4 address
			if !ndefenceUtils.IsValidIPv4Address(ip) {
				continue
			}

			// since the ip address is valid, go ahead and add it to the
			// global array of ip addresses.
			ipAddresses[ip]++

			// check if the line contains the 302 pattern
			redirectChunk := redirectRegex.FindString(line)

			// skip a line if the entry is not the latest date
			if len(redirectChunk) < 1 {
				continue
			}

			// breakup the (potential) redirection section into pieces
			redirectPieces := strings.Split(redirectChunk, " ")

			// safety check, ensure that there are at least 4 pieces
			if len(redirectPieces) < 4 {
				continue
			}

			// attempt to obtain the HTML response code
			htmlCode := redirectPieces[1]

			// if no value is present...
			if len(htmlCode) < 1 {

				// ... skip to the next line
				continue
			}

			// since the value *is* present, check if it is a '302'
			// which refers to a `Found` redirect code
			if htmlCode != "302" {

				// ... else skip to the next line
				continue
			}

			// attempt to obtain the intended redirect location of choice
			redirectLocation := redirectPieces[3]

			// safety check, ensure the value is at least 1 character long
			if len(redirectLocation) < 1 {
				continue
			}

			// attempt to trim it
			redirectLocation = strings.Trim(redirectLocation, "\"")

			// safety check, ensure the value is at least 1 character long
			if len(redirectLocation) < 1 {
				continue
			}

			// since the \t character tends to get mangled easily, add a
			// buffer of single-space characters instead to the IPv4
			// addresses
			spaceFormattedIPAddress, err :=
				ndefenceUtils.SpaceFormatIPv4(ip)

			// if an error occurs, skip to the next element
			if err != nil {
				continue
			}

			// assemble all of the currently gathered info into a log line
			assembledLineString := spaceFormattedIPAddress + " | " +
				htmlCode + " | " + redirectLocation + "\n"

			// append it to the log contents of redirect entries
			redirectLogContents += assembledLineString

			// finally, add the ip address to the list of IPv4 addresses to
			// consider blocking eventually
			if !ndefenceUtils.IsStringInArray(ip, blockedIPAddresses) {
				blockedIPAddresses = append(blockedIPAddresses, ip)
			}

			// increment the line counter
			linesAddedToRedirect++
		}

		// attempt to obtain the whois entries, as a string
		whoisStrings, whoisSummaryMap, err :=
			ndefenceHostname.ObtainWhoisEntries(ipAddresses)

		// if an error occurred, terminate the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// set the title of the whoisLogContents
		whoisLogContents := "Whois Entry Data\n\n"

		// append the date to the whoisLogContents on the next line
		whoisLogContents += genericLogHeader

		// append the whois entry strings to the whois log contents
		whoisLogContents += whoisStrings

		// attempt to stat() the whois.log file, else create it if it does
		// not currently exist
		err = ndefenceIO.StatOrCreateFile(webLocation + whoisLog)

		// if an error occurred during stat(), yet the program was unable
		// to recover or recreate the file, then exit the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// attempt to write the string contents to the ip.log file
		err = ioutil.WriteFile(webLocation+whoisLog,
			[]byte(whoisLogContents),
			0644)

		// convert the ip addresses map into an array of strings
		IPstrings, err := ndefenceHostname.ConvertIPAddressMapToString(
			ipAddresses, whoisSummaryMap)

		// if an error occurred, terminate from the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// attempt to stat() the ip.log file, else create it if it does
		// not currently exist
		err = ndefenceIO.StatOrCreateFile(webLocation + ipLog)

		// if an error occurred during stat(), yet the program was unable
		// to recover or recreate the file, then exit the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// set the title to the IPLogContents
		IPLogContents := "IP Address Counts Data\n\n"

		// append the generic log header to the ip.log file
		IPLogContents += genericLogHeader

		// append the IPstrings content to this point of the log; it will
		// either contain the "IPv4 Address + Daily Count" or a message
		// stating that no addresses appear to be recorded today.
		IPLogContents += IPstrings

		// attempt to write the string contents to the ip.log file
		err = ioutil.WriteFile(webLocation+ipLog,
			[]byte(IPLogContents),
			0644)

		// if an error occurred, terminate the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// if no entries were added to the redirect.log, then add a short
		// message noting that there were no addresses at this time
		if linesAddedToRedirect < 1 {
			redirectLogContents += "No redirections listed at this time."
		}

		// attempt to stat() the ip.log file, else create it if it does
		// not currently exist
		err = ndefenceIO.StatOrCreateFile(webLocation + redirectLog)

		// if an error occurred during stat(), yet the program was unable
		// to recover or recreate the file, then exit the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// having gotten this far, attempt to write the redirect data
		// contents to the log file
		err = ioutil.WriteFile(webLocation+redirectLog,
			[]byte(redirectLogContents),
			0644)

		// if an error occurs, terminate from the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// cycle thru all of the ip address counts...
		for ip, count := range ipAddresses {

			// obtain the country code of this IP address
			givenCountryCode := whoisSummaryMap[ip]

			// safety check, ensure the result is not nil
			if len(givenCountryCode) != 2 || givenCountryCode == ".." {
				continue
			}

			// skip if the country is one of the following:
			//
			// * US --> United States
			// * CA --> Canada
			// * UK --> United Kingdom
			// * FR --> France
			// * DE --> Germany
			// * NL --> Netherlands
			//
			if givenCountryCode == "US" || givenCountryCode == "CA" ||
				givenCountryCode == "UK" || givenCountryCode == "FR" ||
				givenCountryCode == "DE" || givenCountryCode == "NL" {
				continue
			}

			// skip to the next if count is less than 5
			if count < 5 {
				continue
			}

			// go ahead an append to the list of blocked ips
			blockedIPAddresses = append(blockedIPAddresses, ip)
		}

		// attempt to stat() the blocked.log file, else create it if it does
		// not currently exist
		err = ndefenceIO.StatOrCreateFile(webLocation + blockedLog)

		// if an error occurred during stat(), yet the program was unable
		// to recover or recreate the file, then exit the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// if no entries were added to the blocked.log, then add a short
		// message noting that there were no addresses at this time
		blockedLogContents := ""
		if len(blockedIPAddresses) < 1 {
			blockedLogContents += "No IPs blocked at this time."

			// else print the IPs that would have been blocked
		} else {

			// append all of the blocked IPs together, newline separated
			for _, ip := range blockedIPAddresses {
				blockedLogContents += ip + "\n"
			}
		}

		// having gotten this far, attempt to write the blocked data
		// contents to the log file
		err = ioutil.WriteFile(webLocation+blockedLog,
			[]byte(blockedLogContents),
			0644)

		// if an error occurs, terminate from the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		//
		// If a config is specified, attempt to generate a new one
		//
		err = ndefenceUtils.GenerateConfig(defaultSiteConfigPath,
			serverType, blockedIPAddresses, datetime)

		// if an error occurs, terminate from the program
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// if daemon mode is disabled, then exit this loop
		if !daemonMode {
			break
		}

		// take the current time and increment 12 hours
		currentTime := time.Now()
		twelveHoursLater := currentTime.Add(time.Duration(12) * time.Hour)

		// since the user has selected daemon mode, wait 12 hours
		for {

			// grab the current time
			currentTime = time.Now()

			// if 12 hours have passed, go ahead and break
			if currentTime.After(twelveHoursLater) {
				break
			}
		}
	}

	// If all is well, we can return quietly here.
	os.Exit(0)
}
