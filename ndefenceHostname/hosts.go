//
// Utility functions for the hostname / whois / redirect content.
//

package ndefenceHostname

//
// Imports
//
import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"../ndefence_utils"
)

// ConvertIPAddressMapToString ... convert the global IP address map to an
// array of sorted ipEntry objects
/*
 * @param     map        string map containing ip addresses and counts
 * @param     map        string map containing ip/whois country data
 *
 * @return    string     lines that contain "count | ip | country | host \n"
 *            error      error message, if any
 */
func ConvertIPAddressMapToString(ipMap map[string]int,
	whoisCountryMap map[string]string) (string, error) {

	// input validation for the IPv4 map
	if len(ipMap) < 1 {
		return "", fmt.Errorf("ConvertIPAddressMapToString() --> " +
			"IPv4 map appears empty")

		// input validation for the WHOIS country map
	} else if len(whoisCountryMap) < 1 {
		return "", fmt.Errorf("ConvertIPAddressMapToString() --> " +
			"WHOIS country map appears empty\nConsider checking if a " +
			"whois protocol client is installed or if your network " +
			"connection functional")
	}

	// variable declaration
	ipStrings := ""
	tmpStrArray := make([]string, 0)
	var linesAppended uint
	firstHostname := ""

	// for every IPv4 address in the given map...
	for ip := range ipMap {

		// workaround, to better sort IP addresses
		if strings.Index(ip, ".") == 1 {
			ip = "00" + ip
		} else if strings.Index(ip, ".") == 2 {
			ip = "0" + ip
		}

		// append that address to the temp string array
		tmpStrArray = append(tmpStrArray, ip)
	}

	// sort the given list of IPv4 addresses
	sort.Strings(tmpStrArray)

	// for every ip address
	for _, ip := range tmpStrArray {

		// workaround, trim away any LHS zeros
		ip = strings.TrimLeft(ip, "0")

		// grab the count
		count := ipMap[ip]

		// lookup the country code
		countryCode := whoisCountryMap[ip]

		// safety check, fallback to "--" if the country code is blank or
		// nil or unusual length
		if len(countryCode) != 2 {
			countryCode = "--"
		}

		// take the given IP address and attempt to grab the hostname
		hostnames, err := net.LookupAddr(ip)

		// default to "N/A" as the default hostname if an error occurred
		// or no hostnames could be currently found...
		if err != nil || len(hostnames) < 1 {
			firstHostname = "N/A"

		} else if len(hostnames[0]) < 1 {
			// default to "N/A" as the default hostname if the hostname is
			// blank or currently NXDOMAIN and etc.
			firstHostname = "N/A"
		} else {
			// Otherwise go ahead and use the first available hostname
			firstHostname = hostnames[0]
		}

		// since the \t character tends to get mangled easily, add a buffer
		// of single-space characters instead to the IPv4 addresses
		spaceFormattedIPAddress, err := ndefence_utils.SpaceFormatIPv4(ip)

		// if an error occurs, skip to the next element
		if err != nil {
			continue
		}

		// append that count | address |  hostname
		ipStrings += strconv.Itoa(count) + "\t"
		ipStrings += " | "
		ipStrings += spaceFormattedIPAddress
		ipStrings += " | "
		ipStrings += countryCode
		ipStrings += " | "
		ipStrings += firstHostname
		ipStrings += "\n"

		// add a line counter for internal use
		linesAppended++
	}

	// if no ip addresses present, instead append a line about there being
	// no data for today.
	if linesAppended == 0 {
		ipStrings += "No IP addressed listed at this time."
	}

	// everything worked fine, so return the completed string contents
	return ipStrings, nil
}

// ObtainWhoisEntries ... convert the global IP address map to string
// containing whois entries
/*
 * @param     map       string map containing ip addresses and counts
 *
 * @return    string    whois data of every given ip
 * @return    map       string map containing whois country data
 * @return    error     error message, if any
 */
func ObtainWhoisEntries(ipMap map[string]int) (string, map[string]string,
	error) {

	// input validation
	if len(ipMap) < 1 {
		return "", nil, fmt.Errorf("obtainWhoisEntries() --> invalid input")
	}

	// variable declaration
	whoisStrings := ""
	whoisSummaryMap := make(map[string]string)
	var entriesAppended uint
	tmpStrArray := make([]string, 0)
	tmpStrBuffer := ""
	trimmedString := ""
	var err error
	var result bytes.Buffer

	// for every IPv4 address in the given map...
	for ip := range ipMap {

		// workaround, to better sort IP addresses
		if strings.Index(ip, ".") == 1 {
			ip = "00" + ip
		} else if strings.Index(ip, ".") == 2 {
			ip = "0" + ip
		}

		// append that address to the temp string array
		tmpStrArray = append(tmpStrArray, ip)
	}

	// sort the given list of IPv4 addresses
	sort.Strings(tmpStrArray)

	// for every ip address
	for _, ip := range tmpStrArray {

		// workaround, trim away any LHS zeros
		ip = strings.TrimLeft(ip, "0")

		// safety check, skip to the next entry if this one is of length
		// zero
		if len(ip) < 1 {
			continue
		}

		// attempt to obtain the whois record
		result, err = runWhoisCommand(ip)

		// if an error occurs at this point...
		if err != nil {

			// dump the error code to a string
			errorCode := err.Error()

			// if the error code was not 2, then move on to the next IP
			if errorCode != "exit status 2" {
				continue
			}

			// if there is no partial output, then proceed to the next IP
			if len(result.String()) < 1 {
				continue
			}
		}

		// convert the byte buffer to a string
		tmpStrBuffer = result.String()

		// if no record is present, pass back a "N/A"
		if len(tmpStrBuffer) < 1 || tmpStrBuffer == "<nil>" {
			whoisStrings += "Whois Entry for the following: "
			whoisStrings += ip
			whoisStrings += "\n"
			whoisStrings += "N/A\n\n"
			whoisStrings += "---------------------\n\n"
			continue
		}

		// trim it to remove potential whitespace
		trimmedString = strings.Trim(tmpStrBuffer, " ")

		// ensure it still has a length of zero
		if len(trimmedString) < 1 {
			whoisStrings += "Whois Entry for the following: "
			whoisStrings += ip
			whoisStrings += "\n"
			whoisStrings += "N/A\n\n"
			whoisStrings += "---------------------\n\n"
			continue
		}

		// compile a regex that looks for "country: XX\n" or "Country: XX\n"
		re := regexp.MustCompile("[cC]ountry:[^\n]{2,32}\n")

		// variable to hold the country result
		whoisRegexCountryResult := ""

		// attempt to obtain the country of a given IP address, look for at
		// least two matches in case of alt
		whoisRegexCountryResults := re.FindAllString(trimmedString, 2)

		// if there is more than one entry, take the last one since
		// the others are likely ARIN/RIPE/etc data and therefore not
		// quite as useful as the actual origin country network.
		for _, wrc := range whoisRegexCountryResults {
			whoisRegexCountryResult = wrc
		}

		// trim the result
		whoisRegexCountryResult =
			strings.Trim(whoisRegexCountryResult, " ")
		whoisRegexCountryResult =
			strings.Trim(whoisRegexCountryResult, "\n")

		// ensure that the result still has 2 letters
		if len(whoisRegexCountryResult) < 2 {
			whoisRegexCountryResult = "--"
		}

		// certain Brazilian authorities follow an alternate regex,
		// so as a workaround for now, go ahead and test for this
		reBr := regexp.MustCompile("whois.registro.br")
		verifyBr := reBr.FindAllString(trimmedString, 1)

		// if the Brazilian registro is found, go ahead and assign it a
		// country code of BR since this domain probably belongs to Brazil
		if len(verifyBr) > 0 {
			whoisRegexCountryResult = "BR"
		}

		// split up the string using spaces
		wrPieces := strings.Split(whoisRegexCountryResult, " ")

		// safety check, ensure there are one or more pieces
		if len(wrPieces) < 1 {
			whoisRegexCountryResult = "--"
		}

		// assemble a regex to test the country code
		reCountryCode := regexp.MustCompile("^[A-Za-z]{2}$")

		// search thru the pieces for the country code result
		for _, code := range wrPieces {

			// if the code is not equal to 2
			if len(code) != 2 {
				continue
			}

			// ensure the code is actually two alphabet characters
			verify := reCountryCode.FindString(code)

			// skip a line if the entry is not the latest date
			if len(verify) != 2 {
				continue
			}

			// assign the code to the whois country result
			whoisRegexCountryResult = code

			// leave the loop
			break
		}

		// append it to the whois map
		whoisSummaryMap[ip] = strings.ToUpper(whoisRegexCountryResult)

		// otherwise it's probably good, then go ahead and append it
		whoisStrings += "Whois Entry for the following: "
		whoisStrings += ip
		whoisStrings += "\n"
		whoisStrings += trimmedString
		whoisStrings += "\n\n"
		whoisStrings += "---------------------\n\n"

		// since an entry was appended, make a note of it
		entriesAppended++
	}

	// if no ip addresses present, instead append a line about there being
	// no data for today.
	if entriesAppended == 0 {
		whoisStrings += "No whois entries given at this time."
	}

	// everything worked fine, so return the completed string contents
	return whoisStrings, whoisSummaryMap, nil
}

//! Attempt to execute the whois command.
/*
 *  @param    ...string    list of arguments
 *
 *  @return   bytes[]      array of byte buffer data
 */
func runWhoisCommand(args ...string) (bytes.Buffer, error) {

	// variable declaration
	var output bytes.Buffer

	// assemble the command from the list of string arguments
	cmd := exec.Command("whois", args...)
	cmd.Stdout = &output
	cmd.Stderr = &output

	// attempt to execute the command
	err := cmd.Run()

	// if an error occurred, go ahead and pass it back
	if err != nil {
		return output, err
	}

	// having ran the command, pass back the result if no error has
	// occurred
	return output, nil
}
