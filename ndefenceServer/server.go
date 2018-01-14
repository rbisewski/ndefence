//
// Server definition and related functions for ndefence
//

package ndefenceServer

//
// Imports
//
import (
	"fmt"
	"regexp"
)

//
// Server object definition
//
type Server struct {
	Listen     []string
	SSL        bool
	SSLCert    string
	SSLCertKey string
	ServerName string
	Location   []string
	Root       string
	Index      string
	Return     string
}

// ConvertStringsToServers ... parse config file, and return a list of servers
/*
 * @param     string[]    array of lines
 *
 * @return    Server[]    generated Server object
 * @return    error       error message, if any
 *
 * TODO: test this carefully
 */
func ConvertStringsToServers(data []string) ([]Server, error) {

	// input validation
	if len(data) < 1 {
		return nil, fmt.Errorf("convertStringsToServers() --> invalid input")
	}

	// variable declaration
	listOfServers := make([]Server, 0)
	openBracketCount := uint(0)
	closeBracketCount := uint(0)
	currentlyParsingServer := false
	tmpServerStr := make([]string, 0)

	// attempt to assemble a regex to handle
	serverRegex := regexp.MustCompile("^[\t\f\r ]{1,16}server[\t\f\r ]{1,6}[{][\t\f\r ]{1,30}\n$")
	openBracketRegex := regexp.MustCompile("[\t\f\r ]{1,16}[{][\t\f\r ]{1,16}")
	closeBracketRegex := regexp.MustCompile("[\t\f\r ]{1,16}[}][\t\f\r ]{1,16}")

	// for every line of string data...
	for _, line := range data {

		//
		// Currently parsing a Server entry
		//
		if currentlyParsingServer {

			// search for a line that contains `{`
			wasAnOpenBracketFound := openBracketRegex.FindString(line)

			// if an open bracket was found, go ahead and increment the
			// counter
			if len(wasAnOpenBracketFound) > 0 {
				openBracketCount++
				tmpServerStr = append(tmpServerStr, line)
				continue
			}

			// search for a line that contains `}`
			wasCloseBracketFound := closeBracketRegex.FindString(line)

			// if a close bracket was found...
			if len(wasCloseBracketFound) > 0 {

				// go ahead and increment the counter
				closeBracketCount++

				// append the line
				tmpServerStr = append(tmpServerStr, line)

				// if the number of open & close brackets is greater than
				// zero and equal to each other, the server has been completely
				// parsed
				if openBracketCount == closeBracketCount &&
					openBracketCount > 0 && closeBracketCount > 0 {

					// set the flag to false as this logic has since parsed
					// the entire server
					currentlyParsingServer = false

					// take the current string data and attempt to convert it
					// to nginx server entry
					newServer, err := convertToNginxServerEntry(tmpServerStr)

					// if no errors, append it to the list of servers
					if err == nil {
						listOfServers = append(listOfServers, newServer)
					}

					// clear the current array of server strings
					tmpServerStr = nil
				}

				// move on to the next line
				continue
			}

			// otherwise neither an open nor closed bracket was found, so
			// just go ahead and append the line
			tmpServerStr = append(tmpServerStr, line)

			//
			// Not currently parsing a Server entry
			//
		} else {

			// search for a line that contains `server {`
			wasServerEntryFound := serverRegex.FindString(line)

			// if a server entry starting point was not found, go ahead and
			// skip to the next line
			if len(wasServerEntryFound) < 1 {
				continue
			}

			// otherwise a server was found, so set the flag
			currentlyParsingServer = true
		}
	}

	// everything worked fine, so go ahead and return a list of servers
	return listOfServers, nil
}

//! Parse a configuration file, and return a list of servers
/*
 * @param     string[]    array of data
 *
 * @return    Server      generated Server object
 * @return    error       error message, if any
 *
 * TODO: test to ensure this works
 */
func convertToNginxServerEntry(data []string) (Server, error) {

	// input validation
	if len(data) < 1 {
		return Server{}, fmt.Errorf("convertToNginxServerEntry() --> " +
			"invalid input")
	}

	// define a blank and empty new server
	newServer := Server{make([]string, 0), false, "", "", "",
		make([]string, 0), "", "", ""}

	// define a variable to keep track of regex success hits, and a flag to
	// let the parser know that that this is parsing `location {}`
	success := ""
	isThisParsingLocation := false

	// assemble the needed regex
	listenRegex := regexp.MustCompile("^[\t\f\r ]{1,16}listen[\t\f\r ]{1,16}(?.{2,16})[\t\f\r ]{1,16}")
	serverNameRegex := regexp.MustCompile("^[\t\f\r ]{1,16}server_name[\t\f\r ]{1,16}(?.{2,16});")
	rootRegex := regexp.MustCompile("^[\t\f\r ]{1,16}server_name[\t\f\r ]{1,16}(?.{2,32});")
	indexRegex := regexp.MustCompile("^[\t\f\r ]{1,16}index[\t\f\r ]{1,16}(?.{2,32})")
	returnRegex := regexp.MustCompile("^[\t\f\r ]{1,16}return[\t\f\r ]{1,16}(?.{2,32});")
	sslRegex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl[\t\f\r ]{1,16}(?.{1,8});")
	sslCertificateRegex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl_certificate[\t\f\r ]{1,16}(?.{1,8});")
	sslCertificateKeyRegex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl_certificate_key[\t\f\r ]{1,16}(?.{1,8});")
	locationRegex := regexp.MustCompile("^[\t\f\r ]{1,16}location[\t\f\r ]{1,16}(?.{2,16})[\t\f\r ]{1,16}[{]")
	closeBracketRegex := regexp.MustCompile("[\t\f\r ]{1,16}[}][\t\f\r ]{1,16}")

	// cycle thru the list of the data string
	for _, line := range data {

		// if the line is too small, skip it
		if len(line) < 2 {
			continue
		}

		// check for "listen xx;"
		success = listenRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.Listen = append(newServer.Listen, success)
			continue
		}

		// check for "server_name www.example.org;"
		success = serverNameRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.ServerName = success
			continue
		}

		// check for "root /var/www/html;"
		success = rootRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.Root = success
			continue
		}

		// check for "index page.html;"
		success = indexRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.Index = success
			continue
		}

		// check for "return www.example.org/new/page.html;"
		success = returnRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.Return = success
			continue
		}

		// check for "ssl on;"
		success = sslRegex.FindString(line)

		// move on to the next line if the regex successfully determined
		// that SSL is set to on...
		if len(success) > 0 && success == "on" {
			newServer.SSL = true
			continue

			// move on to the next line if the regex successfully determined
			// that SSL is set to off...
		} else if len(success) > 0 && success != "on" {
			newServer.SSL = false
			continue
		}

		// check for "ssl_certificate xxx;"
		success = sslCertificateRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.SSLCert = success
			continue
		}

		// check for "ssl_certificate_key xxx;"
		success = sslCertificateKeyRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			newServer.SSLCertKey = success
			continue
		}

		// check for "location /path/to/site {"
		success = locationRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {
			isThisParsingLocation = true
			newServer.Location = append(newServer.Location, line)
			continue
		}

		// check for "}"
		success = closeBracketRegex.FindString(line)

		// move on to the next line if regex successful
		if len(success) > 0 {

			// hence parsing location is done
			if isThisParsingLocation {
				isThisParsingLocation = false
				newServer.Location = append(newServer.Location, line)
			}

			// move on to the next entry
			continue
		}

		// check if still parsing Location values
		if isThisParsingLocation {

			// then go ahead and append the line
			newServer.Location = append(newServer.Location, line)
			continue
		}
	}

	// since this generated a new server object, pass it back
	return newServer, nil
}

// ConvertServerToString ... convert given Server object into a set of strings
/*
 * @param     Server      given Server object
 *
 * @return    string      printed out version of the Server
 * @return    error       error message, if any
 */
func ConvertServerToString(server Server) (string, error) {

	// input validation
	if len(server.ServerName) < 1 || len(server.Listen) < 1 {
		return "", fmt.Errorf("convertServerToString() --> invalid input")
	}

	output := "server {\n"

	// print out every listen
	for _, l := range server.Listen {

		// ensure that the listen is something sane
		if len(l) < 1 {
			continue
		}

		// listen on port...
		output += "listen " + l + ";\n"
	}

	// append the SSL, if it is enabled
	if server.SSL == true {
		output += "ssl on;\n"
	}

	// if an SSL cert was defined, and SSL is enabled, go ahead and append
	// it to the output
	if server.SSL == true {
		output += "ssl_certificate " + server.SSLCert + ";\n"
	}

	// if an SSL cert key was defined, and SSL is enabled, go ahead and
	// append it to the output
	if server.SSL == true {
		output += "ssl_certificate_key " + server.SSLCertKey + ";\n"
	}

	// append the document root
	output += "root " + server.Root + ";\n"

	// append the index
	output += "index " + server.Index + ";\n"

	// attach the server name, if there is one
	if len(server.ServerName) > 0 {
		output += "server_name " + server.ServerName + ";\n"

		// otherwise default to just the current website location
	} else {
		output += "server_name _;\n"
	}

	// append the return values
	output += "return " + server.Return + ";\n"

	// attach all of the location values
	for _, l := range server.Location {
		output += l
	}

	// append the server end
	output += "}\n"

	// everything worked fine
	return output, nil
}
