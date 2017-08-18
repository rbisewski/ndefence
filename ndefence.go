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
    "fmt"
    "flag"
    "io/ioutil"
    "os"
    "regexp"
    "strings"
    "time"
)

//
// Globals
//
var (

    // Current location of the log directory.
    log_directory = "/var/log/"

    // Name of the access and error log files
    access_log = "access.log"
    error_log  = "error.log"

    // Web location
    web_location = "/var/www/html/data/"

    // Name of the IP log file on the webserver.
    ip_log = "ip.log"

    // Name of the whois log file on the webserver.
    whois_log = "whois.log"

    // Name of the redirect log file on the webserver.
    redirect_log = "redirect.log"

    // Name of the blocked log file on the webserver.
    blocked_log = "blocked.log"

    // Parameter for the server type
    serverType = ""

    // Valid server types
    validServerTypes = []string{"apache", "nginx"}

    // Path to default site config
    default_site_config_path = ""

    // Boolean to flag whether a given server is valid or not
    serverIsValid = false

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
}

//
// PROGRAM MAIN
//
func main() {

    // String variable to hold eventual output, as well error variable.
    var err error = nil

    // Variables to hold the extracted IP addresses and to hold ip
    // addresses to consider blocking, if enough data is gathered
    var ip_addresses = make(map[string] int)
    var blocked_ip_addresses = []string{}

    // Variable to hold a generic log header
    var generic_log_header = ""

    // Variables to hold the log contents written to disk.
    var ip_log_contents string       = ""
    var whois_log_contents string    = ""
    var redirect_log_contents string = ""
    var blocked_log_contents string  = ""

    // Variables to hold the contents of the default site config
    var new_default_site_config_contents string = ""

    // Variable to hold the number of lines added to the redirect log
    var lines_added_to_redirect uint = 0

    // Parse the flags, if any.
    flag.Parse()

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
    _, err = ioutil.ReadDir(web_location)

    // ensure no error occurred
    if err != nil {
        fmt.Println("The following directory does not exist: ",
          web_location)
        os.Exit(1)
    }

    // Assemble the access.log file location.
    access_log_location := log_directory + serverType + "/" + access_log

    // main infinite loop...
    for {

        // Attempt to break up the file into an array of strings a demarked by
        // the newline character.
        lines, err := tokenizeFile(access_log_location, "\n")

        // if an error occurred, print it out and terminate the program
        if err != nil {
            fmt.Println(err)
            os.Exit(0)
        }

        // determine the last valid line
        last_line_num := len(lines)-2

        // safety check, ensure the value is at least zero
        if last_line_num < 0 {
            last_line_num = 0
        }

        // obtain the contents of the last line
        last_line := lines[last_line_num]

        // extract the date of the last line, this is so that the program can
        // gather data concerning only the latest entries
        latest_date_in_log, err := obtainLatestDate(last_line)

        // check if an error occurred
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // attempt to grab the current day/month/year
        datetime := time.Now().Format(time.UnixDate)

        // safety check, ensure this actually got a meaningful string
        if len(datetime) < 1 {
            fmt.Println("Warning: Improper system date-time value" +
              "detected!\n")
            os.Exit(1)
        }

        // since this runs on an infinite loop, clear the contents of
        // the previous generic log header
        generic_log_header = ""

        // assemble the generic log header used by all of the logs
        generic_log_header += "Generated on: " + datetime + "\n"
        generic_log_header += "\n"
        generic_log_header += "Log Data for " + latest_date_in_log + "\n"
        generic_log_header += "-------------------------\n\n"

        // append the title and header to the redirect_log_contents
        redirect_log_contents += "Redirection Entry Data\n\n"
        redirect_log_contents += generic_log_header

        // compile a regex to search for 302 found-redirections
        redirect_capture := "\" 302 [0-9]{1,15} \"(.{2,64})\" "
        redirect_regex := regexp.MustCompile(redirect_capture)

        // turn the latest data string into a regex
        re := regexp.MustCompile(latest_date_in_log)

        // for every line...
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
            if !isValidIPv4Address(ip) {
                continue
            }

            // since the ip address is valid, go ahead and add it to the
            // global array of ip addresses.
            ip_addresses[ip]++

            // check if the line contains the 302 pattern
            redirect_chunk := redirect_regex.FindString(line)

            // skip a line if the entry is not the latest date
            if len(redirect_chunk) < 1 {
                continue
            }

            // breakup the (potential) redirection section into pieces
            redirect_pieces := strings.Split(redirect_chunk, " ")

            // safety check, ensure that there are at least 4 pieces
            if len(redirect_pieces) < 4 {
                continue
            }

            // attempt to obtain the HTML response code
            html_code := redirect_pieces[1]

            // if no value is present...
            if len(html_code) < 1 {

                // ... skip to the next line
                continue
            }

            // since the value *is* present, check if it is a '302'
            // which refers to a `Found` redirect code
            if html_code != "302" {

                // ... else skip to the next line
                continue
            }

            // attempt to obtain the intended redirect location of choice
            redirect_location := redirect_pieces[3]

            // safety check, ensure the value is at least 1 character long
            if len(redirect_location) < 1 {
                continue
            }

            // attempt to trim it
            redirect_location = strings.Trim(redirect_location, "\"")

            // safety check, ensure the value is at least 1 character long
            if len(redirect_location) < 1 {
                continue
            }

            // since the \t character tends to get mangled easily, add a
            // buffer of single-space characters instead to the IPv4
            // addresses
            space_formatted_ip_address, err := spaceFormatIPv4(ip)

            // if an error occurs, skip to the next element
            if err != nil {
               continue
            }

            // assemble all of the currently gathered info into a log line
            assembled_line_string := space_formatted_ip_address + " | " +
              html_code + " | " + redirect_location + "\n"

            // append it to the log contents of redirect entries
            redirect_log_contents += assembled_line_string

            // finally, add the ip address to the list of IPv4 addresses to
            // consider blocking eventually
            if (!isStringInArray(ip, blocked_ip_addresses)) {
                blocked_ip_addresses = append(blocked_ip_addresses, ip)
            }

            // increment the line counter
            lines_added_to_redirect++
        }

        // attempt to obtain the whois entries, as a string
        whois_strings, whois_summary_map, err := obtainWhoisEntries(ip_addresses)

        // if an error occurred, terminate the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // append the title to the whois_log_contents
        whois_log_contents += "Whois Entry Data\n\n"

        // append the date to the whois_log_contents on the next line
        whois_log_contents += generic_log_header

        // append the whois entry strings to the whois log contents
        whois_log_contents += whois_strings

        // attempt to stat() the whois.log file, else create it if it does
        // not currently exist
        err = statOrCreateFile(web_location + whois_log)

        // if an error occurred during stat(), yet the program was unable
        // to recover or recreate the file, then exit the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // attempt to write the string contents to the ip.log file
        err = ioutil.WriteFile(web_location + whois_log,
                               []byte(whois_log_contents),
                               0644)

        // convert the ip addresses map into an array of strings
        ip_strings, err := convertIpAddressMapToString(ip_addresses,
          whois_summary_map)

        // if an error occurred, terminate from the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // attempt to stat() the ip.log file, else create it if it does
        // not currently exist
        err = statOrCreateFile(web_location + ip_log)

        // if an error occurred during stat(), yet the program was unable
        // to recover or recreate the file, then exit the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // append the title to the ip_log_contents
        ip_log_contents += "IP Address Counts Data\n\n"

        // append the generic log header to the ip.log file
        ip_log_contents += generic_log_header

        // append the ip_strings content to this point of the log; it will
        // either contain the "IPv4 Address + Daily Count" or a message stating
        // that no addresses appear to be recorded today.
        ip_log_contents += ip_strings

        // attempt to write the string contents to the ip.log file
        err = ioutil.WriteFile(web_location + ip_log,
                               []byte(ip_log_contents),
                               0644)

        // if an error occurred, terminate the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // if no entries were added to the redirect.log, then add a short
        // message noting that there were no addresses at this time
        if lines_added_to_redirect < 1 {
            redirect_log_contents += "No redirections listed at this time."
        }

        // attempt to stat() the ip.log file, else create it if it does
        // not currently exist
        err = statOrCreateFile(web_location + redirect_log)

        // if an error occurred during stat(), yet the program was unable
        // to recover or recreate the file, then exit the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // having gotten this far, attempt to write the redirect data
        // contents to the log file
        err = ioutil.WriteFile(web_location + redirect_log,
                               []byte(redirect_log_contents),
                               0644)

        // if an error occurs, terminate from the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // cycle thru all of the ip address counts...
        for ip, count := range ip_addresses {

            // obtain the country code of this IP address
            given_country_code := whois_summary_map[ip]

            // safety check, ensure the result is not nil
            if len(given_country_code) != 2 || given_country_code == ".." {
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
            if given_country_code == "US" || given_country_code == "CA" ||
              given_country_code == "UK" || given_country_code == "FR" ||
              given_country_code == "DE" || given_country_code == "NL" {
                continue
            }

            // skip to the next if count is less than 5
            if count < 5 {
                continue
            }

            // go ahead an append to the list of blocked ips
            blocked_ip_addresses = append(blocked_ip_addresses, ip)
        }

        // attempt to stat() the blocked.log file, else create it if it does
        // not currently exist
        err = statOrCreateFile(web_location + blocked_log)

        // if an error occurred during stat(), yet the program was unable
        // to recover or recreate the file, then exit the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // if no entries were added to the blocked.log, then add a short
        // message noting that there were no addresses at this time
        if len(blocked_ip_addresses) < 1 {
            blocked_log_contents += "No IPs blocked at this time."

        // if there *are* IPs that have been requested to block, attempt to
        // generate a list of IP addresses to block, in the form of an
        // nginx 'sites-available' configuration
        } else if len(blocked_ip_addresses) >= 1 && serverType == "nginx" {

            // start with a location chunk
            blocked_log_contents += "location / {\n"

            // append all of the blocked IPs together, newline separated
            for _, ip := range blocked_ip_addresses {
                blocked_log_contents += "deny " + ip + ";\n"
            }

            // terminate with a curl bracket, so signal the end of the
            // server location
            blocked_log_contents += "}\n"

        // otherwise the server is not an nginx, so just print out a list
        // of IPs that would have been blocked
        } else {

            // append all of the blocked IPs together, newline separated
            for _, ip := range blocked_ip_addresses {
                blocked_log_contents += ip + "\n"
            }
        }

        // having gotten this far, attempt to write the blocked data
        // contents to the log file
        err = ioutil.WriteFile(web_location + blocked_log,
                               []byte(blocked_log_contents),
                               0644)

        // if an error occurs, terminate from the program
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        // if the default site config is defined
        if len(default_site_config_path) > 0 {

            // Attempt to break up the file into an array of strings a demarked by
            // the newline character.
            site_config_data, err := tokenizeFile(default_site_config_path, "\n")

            // if an error occurs, terminate from the program
            if err != nil {
                fmt.Println(err)
                os.Exit(1)
            }

            // reading from the above config string data, attempt to convert
            // the string data to a list of servers
            list_of_servers, err := convertStringsToServers(site_config_data)

            // if an error occurs, terminate from the program
            if err != nil {
                fmt.Println(err)
                os.Exit(1)
            }

            // if there is at least one server...
            for _, server := range list_of_servers {

                // TODO: implement the below pseudo code / comments
                server = server

                // verify that the server block was read properly

                // if the server block looks good, go ahead and append it
                // to a string
            }

            // if there is at least one line of server config data appended...
            if len(new_default_site_config_contents) > 0 {

                // TODO: implement the below pseudo code / comments

                // attempt to write it to the file in question

                // if an error occurs, terminate from the program
                if err != nil {
                    fmt.Println(err)
                    os.Exit(1)
                }
            }
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
