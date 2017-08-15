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

    Port uint
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
 */
func convertToNginxServerEntry(data []string) (Server, error) {

    // input validation
    if len(data) < 1 {
        return Server{}, fmt.Errorf("convertToNginxServerEntry() --> " +
          "invalid input")
    }

    // variable declaration
    var new_server Server

    // TODO: implement this function

    // since this generated a new server object, pass it back
    return new_server, nil
}
