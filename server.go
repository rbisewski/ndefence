//
// Server definition and related functions for ndefence
//

//
// Package
//
package main

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
    Listen []string
    SSL bool
    SSL_cert string
    SSL_cert_key string
    Server_name string
    Location []string
    Root string
    Index string
    Return string
}

//! Parse a configuration file, and return a list of servers
/*
 * @param     string[]    array of lines
 *
 * @return    Server[]    generated Server object
 * @return    error       error message, if any
 *
 * TODO: test this carefully
 */
func convertStringsToServers(string_data []string) ([]Server,
  error) {

    // input validation
    if len(string_data) < 1 {
        return nil, fmt.Errorf("convertStringsToServers() --> invalid input")
    }

    // variable declaration
    var list_of_servers = make([]Server, 0)
    var open_bracket_count uint = 0
    var close_bracket_count uint = 0
    var currently_parsing_a_server bool = false
    var tmp_server_str []string = make([]string, 0)

    // attempt to assemble a regex to handle
    server_regex := regexp.MustCompile("^[\t\f\r ]{1,16}server[\t\f\r ]{1,6}[{][\t\f\r ]{1,30}\n$")
    open_bracket_regex := regexp.MustCompile("[\t\f\r ]{1,16}[{][\t\f\r ]{1,16}")
    close_bracket_regex := regexp.MustCompile("[\t\f\r ]{1,16}[}][\t\f\r ]{1,16}")

    // for every line of string data...
    for _, line := range string_data {

        //
        // Currently parsing a Server entry
        //
        if currently_parsing_a_server {

            // search for a line that contains `{`
            was_an_open_bracket_found := open_bracket_regex.FindString(line)

            // if an open bracket was found, go ahead and increment the
            // counter
            if len(was_an_open_bracket_found) > 0 {
                open_bracket_count++
                tmp_server_str = append(tmp_server_str, line)
                continue
            }

            // search for a line that contains `}`
            was_a_close_bracket_found := close_bracket_regex.FindString(line)

            // if a close bracket was found...
            if len(was_a_close_bracket_found) > 0 {

                // go ahead and increment the counter
                close_bracket_count++

                // append the line
                tmp_server_str = append(tmp_server_str, line)

                // if the number of open & close brackets is greater than
                // zero and equal to each other, the server has been completely
                // parsed
                if open_bracket_count == close_bracket_count &&
                  open_bracket_count > 0 && close_bracket_count > 0 {

                    // set the flag to false as this logic has since parsed
                    // the entire server
                    currently_parsing_a_server = false

                    // take the current string data and attempt to convert it
                    // to nginx server entry
                    new_server, err := convertToNginxServerEntry(tmp_server_str)

                    // if no errors, append it to the list of servers
                    if err == nil {
                        list_of_servers = append(list_of_servers, new_server)
                    }

                    // clear the current array of server strings
                    tmp_server_str = nil
                }

                // move on to the next line
                continue
            }

            // otherwise neither an open nor closed bracket was found, so
            // just go ahead and append the line
            tmp_server_str = append(tmp_server_str, line)

        //
        // Not currently parsing a Server entry
        //
        } else {

            // search for a line that contains `server {`
            was_a_server_entry_found := server_regex.FindString(line)

            // if a server entry starting point was not found, go ahead and
            // skip to the next line
            if len(was_a_server_entry_found) < 1 {
                continue
            }

            // otherwise a server was found, so set the flag
            currently_parsing_a_server = true
        }
    }

    // everything worked fine, so go ahead and return a list of servers
    return list_of_servers, nil
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
    var new_server Server = Server{make([]string, 0), false, "", "", "",
      make([]string, 0), "", "", ""}

    // define a variable to keep track of regex success hits, and a flag to
    // let the parser know that that this is parsing `location {}`
    var success string = ""
    var isThisParsingLocation bool = false

    // assemble the needed regex
    listen_regex := regexp.MustCompile("^[\t\f\r ]{1,16}listen[\t\f\r ]{1,16}(?.{2,16})[\t\f\r ]{1,16}")
    server_name_regex := regexp.MustCompile("^[\t\f\r ]{1,16}server_name[\t\f\r ]{1,16}(?.{2,16});")
    root_regex := regexp.MustCompile("^[\t\f\r ]{1,16}server_name[\t\f\r ]{1,16}(?.{2,32});")
    index_regex := regexp.MustCompile("^[\t\f\r ]{1,16}index[\t\f\r ]{1,16}(?.{2,32})")
    return_regex := regexp.MustCompile("^[\t\f\r ]{1,16}return[\t\f\r ]{1,16}(?.{2,32});")
    ssl_regex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl[\t\f\r ]{1,16}(?.{1,8});")
    ssl_certificate_regex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl_certificate[\t\f\r ]{1,16}(?.{1,8});")
    ssl_certificate_key_regex := regexp.MustCompile("^[\t\f\r ]{1,16}ssl_certificate_key[\t\f\r ]{1,16}(?.{1,8});")
    location_regex := regexp.MustCompile("^[\t\f\r ]{1,16}location[\t\f\r ]{1,16}(?.{2,16})[\t\f\r ]{1,16}[{]")
    close_bracket_regex := regexp.MustCompile("[\t\f\r ]{1,16}[}][\t\f\r ]{1,16}")

    // cycle thru the list of the data string
    for _, line := range data {

        // if the line is too small, skip it
        if len(line) < 2 {
            continue
        }

        // check for "listen xx;"
        success = listen_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.Listen = append(new_server.Listen, success)
            continue
        }

        // check for "server_name www.example.org;"
        success = server_name_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.Server_name = success
            continue
        }

        // check for "root /var/www/html;"
        success = root_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.Root = success
            continue
        }

        // check for "index page.html;"
        success = index_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.Index = success
            continue
        }

        // check for "return www.example.org/new/page.html;"
        success = return_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.Return = success
            continue
        }

        // check for "ssl on;"
        success = ssl_regex.FindString(line)

        // move on to the next line if the regex successfully determined
        // that SSL is set to on...
        if len(success) > 0 && success == "on" {
            new_server.SSL = true
            continue

        // move on to the next line if the regex successfully determined
        // that SSL is set to off...
        } else if len(success) > 0 && success != "on" {
            new_server.SSL = false
            continue
        }

        // check for "ssl_certificate xxx;"
        success = ssl_certificate_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.SSL_cert = success
            continue
        }

        // check for "ssl_certificate_key xxx;"
        success = ssl_certificate_key_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            new_server.SSL_cert_key = success
            continue
        }

        // check for "location /path/to/site {"
        success = location_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {
            isThisParsingLocation = true
            new_server.Location = append(new_server.Location, line)
            continue
        }

        // check for "}"
        success = close_bracket_regex.FindString(line)

        // move on to the next line if regex successful
        if len(success) > 0 {

            // hence parsing location is done
            if isThisParsingLocation {
                isThisParsingLocation = false
                new_server.Location = append(new_server.Location, line)
            }

            // move on to the next entry
            continue
        }

        // check if still parsing Location values
        if isThisParsingLocation {

            // then go ahead and append the line
            new_server.Location = append(new_server.Location, line)
            continue
        }
    }

    // since this generated a new server object, pass it back
    return new_server, nil
}
