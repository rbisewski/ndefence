//
// Misc utility functions for ndefence
//

package ndefenceUtils

//
// Imports
//
import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"../ndefenceIO"
)

// IsValidIPv6Address ... validate an IPv6 address
/*
 * @param     string    /path/to/file
 *
 * @return    bool      whether or not this is true
 *
 * TODO: add more logic to this function
 */
func IsValidIPv6Address(ip string) bool {

	// input validation
	if len(ip) < 1 {
		return false
	}

	// variable declaration
	wasEveryPieceBlank := true

	// attempt to split the string into pieces via the ':' char
	ipPieces := strings.Split(ip, ":")

	// safety check, ensure there is at least one piece
	if len(ipPieces) < 1 {
		return false
	}

	// for every hexadecimal piece of the IPv6 address...
	for _, hexa := range ipPieces {

		// if the hexadecimal was blank, go ahead and switch over to
		// the next element, since the IPv6 spec does allow for some
		// elements to be blank, in certain situations...
		if len(hexa) == 0 {
			continue

			// ensure it has a length between 1 and 4
		} else if len(hexa) < 1 || len(hexa) > 4 {
			return false
		}

		// convert the ip_piece string to an integer
		hexaAsUint, err := strconv.ParseUint(hexa, 16, 64)

		// if an error occurs, go ahead and return false
		if err != nil {
			return false
		}

		// if greater than 0xFFFF pass back a false
		if hexaAsUint > 65535 {
			return false
		}

		// having gotten this far, then at least 1 of the hexademical
		// chunks was non-blank, so set the flag
		wasEveryPieceBlank = false
	}

	// in the scenario where every case was blank, then some silly input
	// like ":::::::" was given, so return false here
	if wasEveryPieceBlank {
		return false
	}

	// if all the tests passed, go ahead and return true
	return true
}

// IsValidIPv4Address ... validate an IPv4 address
/*
 * @param     string    /path/to/file
 *
 * @return    bool      whether or not this is true
 */
func IsValidIPv4Address(ip string) bool {

	// input validation
	if len(ip) < 1 {
		return false
	}

	// ensure that the ip address is valid length
	//
	// 0.0.0.0 --> 8 chars (min)
	//
	// 127.123.123.123 --> 15 chars (max)
	//
	if len(ip) < 8 || len(ip) > 15 {
		return false
	}

	// attempt to split the string into pieces via the '.' char
	ipPieces := strings.Split(ip, ".")

	// ensure that there are at least 4 pieces
	if len(ipPieces) != 4 {
		return false
	}

	// for every oct piece of the IPv4 address...
	for _, oct := range ipPieces {

		// ensure it has a length of at least 1
		if len(oct) < 1 {
			return false
		}

		// convert the ip_piece string to an integer
		octAsUint, err := strconv.ParseUint(oct, 0, 10)

		// if an error occurred, throw back a false
		if err != nil {
			return false
		}

		// ensure that the integer is between 0 and 255; actually it is a
		// unsigned int at this point, so only need check if > 255
		if octAsUint > 255 {
			return false
		}
	}

	// otherwise it appears to be a proper IPv4
	return true
}

// SpaceFormatIPv4 ... take a given IP address and space buffer it so that
// it is always 15 characters long.
/*
 * @param    string    IPv4 address
 *
 * @param    string    space-formatted IPv4 address
 * @param    error     error message, if any
 */
func SpaceFormatIPv4(ip string) (string, error) {

	// input validation
	if len(ip) < 1 || len(ip) > 15 {
		return "", fmt.Errorf("spaceFormatIPv4() --> invalid input")
	}

	// ensure this is actually a IPv4 address
	if !IsValidIPv4Address(ip) {
		return "", fmt.Errorf("spaceFormatIPv4() --> given IP is not " +
			"an IPv4 address\n")
	}

	// attempt to format the IPv4 address
	spaceFormattedIPAddress := ip
	for len(spaceFormattedIPAddress) < 16 {
		spaceFormattedIPAddress += " "
	}

	// return the formatted IPv4 string
	return spaceFormattedIPAddress, nil
}

// ObtainSlash24FromIpv4 ... convert a given IPv4 address to a x.x.x.0/24
// CIDR notation
/*
 * @param    string    an IPv4 address
 *
 * @return   string    result as a /24
 * @return   error     error message, if any
 */
func ObtainSlash24FromIpv4(ip string) (string, error) {

	// input validation
	if len(ip) < 1 {
		return "", fmt.Errorf("obtainSlash24FromIpv4() --> invalid input")
	}

	// ensure the given value is actually an IP4 address
	if !IsValidIPv4Address(ip) {
		return "", fmt.Errorf("obtainSlash24FromIpv4() --> improper " +
			"IPv4 address given")
	}

	// variable declaration
	ipv4Slash24Cidr := ""

	// separate the IPv4 address string into pieces
	ipPieces := strings.Split(ip, ".")

	// ensure that there are at least 4 pieces
	if len(ipPieces) != 4 {
		return "", fmt.Errorf("obtainSlash24FromIpv4() --> " +
			"non-standard IPv4 address")
	}

	// reconstruct the IPv4 address string
	ipv4Slash24Cidr += ipPieces[0]
	ipv4Slash24Cidr += "."
	ipv4Slash24Cidr += ipPieces[1]
	ipv4Slash24Cidr += "."
	ipv4Slash24Cidr += ipPieces[2]
	ipv4Slash24Cidr += "."
	ipv4Slash24Cidr += "0/24"

	// having gone this far, return the adjusted result
	return ipv4Slash24Cidr, nil
}

// ReadBlockedIPConfig ... read blocked ip values and return as an array
/*
 * @param    string      /path/to/blockedips.cfg
 * @param    string      server type (nginx, apache2, etc)
 * @param    string      Datetime, as a string
 *
 * @return   map         map[IPv4 Address] = timestamp, in seconds
 * @return   error       error message, if any
 */
func ReadBlockedIPConfig(path string, stype string,
	datetime string) (map[string]int, error) {

	// input validation
	if path == "" || stype == "" || datetime == "" {
		return nil, fmt.Errorf("ReadBlockedIPConfig() --> invalid " +
			"input")
	}

	listOfBlockedIPs := make(map[string]int, 0)

	lines, err := ndefenceIO.TokenizeFile(path, "\n")
	if err != nil {
		return nil, err
	}

	for _, line := range lines {

		//
		// IP addresses in the blocked IPs file should be in the
		// form of "address # timestamp" or "address # perma" like
		// the example below:
		//
		// 127.0.0.1 # perma
		// 10.0.0.2 # 1516569627
		//
		pieces := strings.Split(line, "#")

		if len(pieces) != 2 {
			continue
		}

		if pieces[0] == "" || pieces[1] == "" {
			continue
		}

		// remove the "deny " at the start of the entry
		possibleIP := strings.TrimSpace(pieces[0])
		possibleIP = strings.Trim(possibleIP, "deny")

		// trim and validate the IP
		ip := strings.TrimSpace(possibleIP)
		if !IsValidIPv4Address(ip) {
			continue
		}

		// trim the timestamp string
		timestampStr := strings.TrimSpace(pieces[1])
		if timestampStr == "" {
			continue
		}

		// perma entries will stay blocked forever
		if timestampStr == "perma" {
			listOfBlockedIPs[ip] = -1
			continue
		}

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			continue
		}

		currentTime, err := strconv.ParseInt(datetime, 10, 64)
		if err != nil {
			continue
		}

		// if the IP has been blocked for 48 hours in seconds, skip
		// it since it has been blocked long enough
		if currentTime-timestamp > 172800 {
			continue
		}

		listOfBlockedIPs[ip] = int(timestamp)
	}

	return listOfBlockedIPs, nil
}

// IsStringInArray ... check if a given string value is present in a
// string array
/*
 *  @param    string      string value in question
 *  @param    []string    array of string values
 *
 *  @return   bool        whether or not it is present
 */
func IsStringInArray(str string, stringArray []string) bool {

	// input validation
	if len(str) < 1 || str == "" || len(stringArray) < 1 {
		return false
	}

	// cycle thru the array
	for _, s := range stringArray {
		if str == s {
			return true
		}
	}

	// otherwise assume it is not present
	return false
}

//RunNginxReloadCommand ... Attempt to execute a given command.
/*
 *  @param    none
 *
 *  @return   bytes[]      array of byte buffer data
 */
func RunNginxReloadCommand() (bytes.Buffer, error) {

	// variable declaration
	var output bytes.Buffer

	// assemble the command from the list of string arguments
	cmd := exec.Command("service nginx reload")
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

// RunApacheReloadCommand ... attempt to execute a given command.
/*
 *  @param    none
 *
 *  @return   bytes[]      array of byte buffer data
 */
func RunApacheReloadCommand() (bytes.Buffer, error) {

	// variable declaration
	var output bytes.Buffer

	// assemble the command from the list of string arguments
	cmd := exec.Command("service apache2 reload")
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
