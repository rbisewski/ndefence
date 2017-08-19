//
// File functions for ndefence
//

//
// Package
//
package ndefence_io

//
// Imports
//
import (
    "fmt"
    "io/ioutil"
    "os"
    "strings"
)

//! Convert a file into a string array as per a given separator
/*
 * @param     string      /path/to/file
 * @param     string      tokenizer character sequence
 *
 * @return    string[]    array of lines
 */
func TokenizeFile(filepath string, separator string) ([]string,
  error) {

    // input validation
    if len(filepath) < 1 || len(separator) < 1 {
        return nil, fmt.Errorf("tokenizeFile() --> invalid input")
    }

    // Check if access log file actually exists.
    byte_contents, err := ioutil.ReadFile(filepath)

    // if an error occurs at this point, it is due to the program being
    // unable to access a read the file, so pass back an error
    if err != nil {
        return nil, fmt.Errorf("tokenizeFile() --> An error occurred " +
          "while trying to read the following file: ", filepath)
    }

    // dump the contents of the file to a string
    string_contents := string(byte_contents)

    // if the contents are less than 1 byte, mention that via error
    if len(string_contents) < 1 {
        return nil, fmt.Errorf("tokenizeFile() --> the following file " +
          "was empty: ", filepath)
    }

    // attempt to break up the file into an array of strings
    str_array := strings.Split(string_contents, separator)

    // terminate the program if the array has less than 1 element
    if len(str_array) < 1 {
        return nil, fmt.Errorf("tokenizeFile() --> no string data was " +
          "found")
    }

    // having obtained the lines of data, pass them back
    return str_array, nil
}

//! Stat if a given file exists at specified path, else create it.
/*
 * @param     string    /path/to/filename
 *
 * @return    error     error message, if any
 */
func StatOrCreateFile(path string) error {

    // input validation, ensure the file location is sane
    if len(path) < 1 {
        return fmt.Errorf("statOrCreateFile() --> invalid input")
    }

    // variable declaration
    var fileNotFoundAndWasCreated bool = false

    // attempt to stat() if the whois.log file even exists
    _, err := os.Stat(path)

    // attempt check if the file exists at the given path
    if os.IsNotExist(err) {

        // if not, then create it
        f, creation_err := os.Create(path)

        // if an error occurred during creation, terminate program
        if creation_err != nil {
            return creation_err
        }

        // then go ahead and close the file connection for the time being
        f.Close()

        // if the program go to actually create the file, go ahead and
        // set this flag to true
        fileNotFoundAndWasCreated = true
    }

    // if an error occurred during stat(), yet the program was unable
    // to recover or recreate the file, then exit the program
    if err != nil && !fileNotFoundAndWasCreated {
        return err
    }

    // else everything worked, so go ahead and return nil
    return nil
}

//! Determine the latest date present in the logs
/*
 * @param     string    line data
 *
 * @return    string    latest time-date, in the form of DD/MMM/YYYY
 *            error     error message, if any
 */
func ObtainLatestDate(line_data string) (string, error) {

    // input validation
    if len(line_data) < 1 {
        return "", fmt.Errorf("obtainLatestDate() --> invalid input")
    }

    // variable declaration
    var result string = ""

    // attempt to split that line via spaces
    elements := strings.Split(line_data, " ")

    // safety check, ensure there are at least 4 elements
    if len(elements) < 4 {

        // otherwise send back an error
        return "", fmt.Errorf("obtainLatestDate() --> poorly formatted line")
    }

    // attempt to grab the fourth element
    datetime := elements[3]

    // attempt to trim the string of [ and ] brackets
    datetime = strings.Trim(datetime, "[]")

    // ensure the string actually has at least a length of 1
    if len(datetime) < 1 {
        return "", fmt.Errorf("obtainLatestDate() --> date-time string " +
          "is of improper length")
    }

    // split the string via the ':' characters
    time_pieces := strings.SplitAfter(datetime, ":")

    // ensure there is at least one element
    if len(time_pieces) < 1 || len(time_pieces[0]) < 1 {
        return "", fmt.Errorf("obtainLatestDate() --> unable to use _:_ " +
          "chars to separate time into pieces")
    }

    // trim away the remaining : chars
    result = strings.Trim(time_pieces[0], ":")

    // final safety check, ensure that the result has a len > 0
    if len(result) < 1 {

        // otherwise send back an error
        return "", fmt.Errorf("obtainLatestDate() --> unable to " +
          "assemble string result")
    }

    // if everything turned out fine, go ahead and return
    return result, nil
}

