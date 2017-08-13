//
// Utility functions for the hostname / whois / redirect content.
//

//
// Package
//
package main

//
// Imports
//
import (
    "bytes"
    "fmt"
    "net"
    "os/exec"
    "regexp"
    "strings"
    "sort"
    "strconv"
)

//! Convert the global IP address map to an array of sorted ipEntry objects
/*
 * @param     map        string map containing ip addresses and counts
 * @param     map        string map containing ip/whois country data
 *
 * @return    string     lines that contain "count | ip | country | host \n"
 *            error      error message, if any
 */
func convertIpAddressMapToString(ip_map map[string] int,
  whois_country_map map[string] string) (string, error) {

    // input validation
    if len(ip_map) < 1 || len(whois_country_map) < 1 {
        return "", fmt.Errorf("convertIpAddressMapToString() --> " +
          "invalid input")
    }

    // variable declaration
    var ip_strings string     = ""
    var tmp_str_array         = make([]string, 0)
    var lines_appended uint   = 0
    var first_hostname string = ""

    // for every IPv4 address in the given map...
    for ip, _ := range ip_map {

        // workaround, to better sort IP addresses
        if strings.Index(ip, ".") == 1 {
            ip = "00" + ip
        } else if strings.Index(ip, ".") == 2 {
            ip = "0" + ip
        }

        // append that address to the temp string array
        tmp_str_array = append(tmp_str_array, ip)
    }

    // sort the given list of IPv4 addresses
    sort.Strings(tmp_str_array)

    // for every ip address
    for _, ip := range tmp_str_array {

        // workaround, trim away any LHS zeros
        ip = strings.TrimLeft(ip, "0")

        // grab the count
        count := ip_map[ip]

        // lookup the country code
        country_code := whois_country_map[ip]

        // safety check, fallback to "--" if the country code is blank or
        // nil or unusual length
        if len(country_code) != 2 {
            country_code = "--"
        }

        // take the given IP address and attempt to grab the hostname
        hostnames, err := net.LookupAddr(ip)

        // default to "N/A" as the default hostname if an error occurred
        // or no hostnames could be currently found...
        if err != nil || len(hostnames) < 1 {
            first_hostname = "N/A"

        // default to "N/A" as the default hostname if the hostname is
        // blank or currently NXDOMAIN and etc.
        } else if len(hostnames[0]) < 1 {
            first_hostname = "N/A"

        // Otherwise go ahead and use the first available hostname
        } else {
            first_hostname = hostnames[0]
        }

        // since the \t character tends to get mangled easily, add a buffer
        // of single-space characters instead to the IPv4 addresses
        space_formatted_ip_address, err := spaceFormatIPv4(ip)

        // if an error occurs, skip to the next element
        if err != nil {
           continue
        }

        // append that count | address |  hostname
        ip_strings += strconv.Itoa(count) + "\t"
        ip_strings += " | "
        ip_strings += space_formatted_ip_address
        ip_strings += " | "
        ip_strings += country_code
        ip_strings += " | "
        ip_strings += first_hostname
        ip_strings += "\n"

        // add a line counter for internal use
        lines_appended++
    }

    // if no ip addresses present, instead append a line about there being
    // no data for today.
    if lines_appended == 0 {
        ip_strings += "No IP addressed listed at this time."
    }

    // everything worked fine, so return the completed string contents
    return ip_strings, nil
}

//! Convert the global IP address map to string containing whois entries
/*
 * @param     map       string map containing ip addresses and counts
 *
 * @return    string    whois data of every given ip
 * @return    map       string map containing whois country data
 * @return    error     error message, if any
 */
func obtainWhoisEntries(ip_map map[string] int) (string, map[string] string,
  error) {

    // input validation
    if len(ip_map) < 1 {
        return "", nil, fmt.Errorf("obtainWhoisEntries() --> invalid input")
    }

    // variable declaration
    var whois_strings string  = ""
    var whois_summary_map     = make(map[string] string)
    var entries_appended uint = 0
    var tmp_str_array         = make([]string, 0)
    var tmp_str_buffer        = ""
    var trimmed_string        = ""
    var err error
    var result bytes.Buffer

    // for every IPv4 address in the given map...
    for ip, _ := range ip_map {

        // workaround, to better sort IP addresses
        if strings.Index(ip, ".") == 1 {
            ip = "00" + ip
        } else if strings.Index(ip, ".") == 2 {
            ip = "0" + ip
        }

        // append that address to the temp string array
        tmp_str_array = append(tmp_str_array, ip)
    }

    // sort the given list of IPv4 addresses
    sort.Strings(tmp_str_array)

    // for every ip address
    for _, ip := range tmp_str_array {

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
            error_code := err.Error()

            // if the error code was not 2, then move on to the next IP
            if error_code != "exit status 2" {
                continue
            }

            // if there is no partial output, then proceed to the next IP
            if len(result.String()) < 1 {
                continue
            }
        }

        // convert the byte buffer to a string
        tmp_str_buffer = result.String()

        // if no record is present, pass back a "N/A"
        if len(tmp_str_buffer) < 1 || tmp_str_buffer == "<nil>" {
            whois_strings += "Whois Entry for the following: "
            whois_strings += ip
            whois_strings += "\n"
            whois_strings += "N/A\n\n"
            whois_strings += "---------------------\n\n"
            continue
        }

        // trim it to remove potential whitespace
        trimmed_string = strings.Trim(tmp_str_buffer, " ")

        // ensure it still has a length of zero
        if len(trimmed_string) < 1 {
            whois_strings += "Whois Entry for the following: "
            whois_strings += ip
            whois_strings += "\n"
            whois_strings += "N/A\n\n"
            whois_strings += "---------------------\n\n"
            continue
        }

        // compile a regex that looks for "country: XX\n" or "Country: XX\n"
        re := regexp.MustCompile("[cC]ountry:[^\n]{2,32}\n")

        // variable to hold the country result
        whois_regex_country_result := ""

        // attempt to obtain the country of a given IP address, look for at
        // least two matches in case of alt
        whois_regex_country_results := re.FindAllString(trimmed_string, 2)

        // if there is more than one entry, take the last one since
        // the others are likely ARIN/RIPE/etc data and therefore not
        // quite as useful as the actual origin country network.
        for _, wrc := range whois_regex_country_results {
            whois_regex_country_result = wrc
        }

        // trim the result
        whois_regex_country_result =
          strings.Trim(whois_regex_country_result, " ")
        whois_regex_country_result =
          strings.Trim(whois_regex_country_result, "\n")

        // ensure that the result still has 2 letters
        if len(whois_regex_country_result) < 2 {
            whois_regex_country_result = "--"
        }

        // certain Brazilian authorities follow an alternate regex,
        // so as a workaround for now, go ahead and test for this
        re_br := regexp.MustCompile("whois.registro.br")
        verify_br := re_br.FindAllString(trimmed_string, 1)

        // if the Brazilian registro is found, go ahead and assign it a
        // country code of BR since this domain probably belongs to Brazil
        if len(verify_br) > 0 {
            whois_regex_country_result = "BR"
        }

        // split up the string using spaces
        wr_pieces := strings.Split(whois_regex_country_result, " ")

        // safety check, ensure there are one or more pieces
        if len(wr_pieces) < 1 {
            whois_regex_country_result = "--"
        }

        // assemble a regex to test the country code
        re_country_code := regexp.MustCompile("^[A-Za-z]{2}$")

        // search thru the pieces for the country code result
        for _, code := range wr_pieces {

            // if the code is not equal to 2
            if len(code) != 2 {
                continue
            }

            // ensure the code is actually two alphabet characters
            verify := re_country_code.FindString(code)

            // skip a line if the entry is not the latest date
            if len(verify) != 2 {
                continue
            }

            // assign the code to the whois country result
            whois_regex_country_result = code

            // leave the loop
            break
        }

        // append it to the whois map
        whois_summary_map[ip] = strings.ToUpper(whois_regex_country_result)

        // otherwise it's probably good, then go ahead and append it
        whois_strings += "Whois Entry for the following: "
        whois_strings += ip
        whois_strings += "\n"
        whois_strings += trimmed_string
        whois_strings += "\n\n"
        whois_strings += "---------------------\n\n"

        // since an entry was appended, make a note of it
        entries_appended++
    }

    // if no ip addresses present, instead append a line about there being
    // no data for today.
    if entries_appended == 0 {
        whois_strings += "No whois entries given at this time."
    }

    // everything worked fine, so return the completed string contents
    return whois_strings, whois_summary_map, nil
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
