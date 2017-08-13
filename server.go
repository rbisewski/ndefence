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
 */
func convertStringsToServers(string_data []string) ([]Server,
  error) {

  // input validation
  if len(string_data) < 1 {
      return nil, fmt.Errorf("convertStringsToServers() --> invalid input")
  }

  // variable declaration
  var list_of_servers []Server

  // TODO: implemen this function

  // everything worked fine, so go ahead and return a list of servers
  return list_of_servers, nil
}
