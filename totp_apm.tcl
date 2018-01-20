when ACCESS_POLICY_AGENT_EVENT {
    switch [ACCESS::policy agent_id] {
        "get_totp_key" {
            ### TOTP key settings ###
        
            # key (shared secret) storage method: ldap, ad, or datagroup
            set totp_key_storage "datagroup"
        
            # LDAP attribute for key if storing in LDAP (optional)
            set totp_key_ldap_attr "totp_auth_key"

            # Active Directory attribute for key if storing in AD (optional)
            set totp_key_ad_attr "totp_auth_key"
        
            # datagroup name if storing key in a datagroup (optional)
            set totp_key_dg "totp_auth_keys"

            #####################################
            ### DO NOT MODIFY BELOW THIS LINE ###
            #####################################
        
            # set variables from APM logon page
            set username [ACCESS::session data get session.logon.last.username]
        
            # retrieve key from specified storage
            set totp_key ""
                
            switch $totp_key_storage {
                ldap {
                    set totp_key [ACCESS::session data get session.ldap.last.attr.${totp_key_ldap_attr}]
                }
                ad {
                    set totp_key [ACCESS::session data get session.ad.last.attr.${totp_key_ad_attr}]
                }
                datagroup {
                    set totp_key [class lookup $username $totp_key_dg]
                }
            }
        
            # set code verification result in session variable
            if {$totp_key ne ""} {
                ACCESS::session data set -secure session.custom.totp.key $totp_key
            }
        }
        "check_totp_code" {
            ### TOTP verification settings ###
        
            # logon page session variable name for code attempt form field
            set totp_code_form_field "totp_code"
        
            # How many periods slow or fast should we allow clients to be?
            set totp_tolerance 1
            # How long will users be locked out for?
            set totp_lockout_period 90
            # How many submissions per period before lockout?
            set totp_lockout_rate 3
            
            set totp_used_codes_table    "[virtual name]_totp_used_codes"
            set totp_lockout_state_table "[virtual name]_totp_lockout_state"

            #####################################
            ### DO NOT MODIFY BELOW THIS LINE ###
            #####################################
        
            # set variables from APM logon page
            set username  [ACCESS::session data get session.logon.last.username]
            # Fetch submitted code, stripping all whitespace
            set totp_code [join [ACCESS::session data get session.logon.last.${totp_code_form_field}] ""]
        
            # retrieve key obtained via previous call to totp_get_key
            set totp_key [ACCESS::session data get -secure session.custom.totp.key]
            # Pull fields out of totp_key
            set totp_algorithm [lindex $totp_key 0]
            set totp_secret    [lindex $totp_key 1]
            set totp_digits    [lindex $totp_key 2]
            set totp_period    [lindex $totp_key 3]
            
            # Update TOTP lockout state table
            set totp_rate [table incr -notouch -subtable $totp_lockout_state_table $username]
            table timeout -subtable $totp_lockout_state_table $username $totp_lockout_period

            # Check TOTP lockout rate hasn't been exceeded
            if { $totp_rate <= $totp_lockout_rate } {
                # Check that the user has submitted a code
                if { $totp_code ne "" } {
                    set totp_secret_len [string length $totp_secret]
                    # Check that the key length is a multiple of 16
                    if { $totp_secret_len > 0 && [expr $totp_secret_len % 16] == 0 } {

                        # Decode Base32-encoded TOTP key to binary

                        # Base32 alphabet (see RFC 4648)
                        array set b32_alphabet {
                            A 0  B 1  C 2  D 3
                            E 4  F 5  G 6  H 7
                            I 8  J 9  K 10 L 11
                            M 12 N 13 O 14 P 15
                            Q 16 R 17 S 18 T 19
                            U 20 V 21 W 22 X 23
                            Y 24 Z 25 2 26 3 27
                            4 28 5 29 6 30 7 31
                        }

                        set totp_secret [string toupper $totp_secret]
                        set n 0
                        set j 0
                        set K ""

                        for { set i 0 } { $i < $totp_secret_len } { incr i } {
                            set n [expr $n << 5]
                            set n [expr $n + $b32_alphabet([string index $totp_secret $i])]
                            set j [incr j 5]

                            if { $j >= 8 } {
                                set j [incr j -8]
                                append K [format %c [expr ($n & (0xFF << $j)) >> $j]]
                            }
                        }
                        # Finished Base32 decode
                        
                        # HMAC initialisation
                        set K_len [string length $K]
                        if {$K_len > 64} {
                            set K [$totp_algorithm $K]
                        } else {
                            set pad [expr {64 - $K_len}]
                            append K [string repeat \0 $pad]
                        }
                        
                        set Ki {}
                        set Ko {}
                        binary scan $K i16 Ks
                        foreach k $Ks {
                            append Ki [binary format i [expr {$k ^ 0x36363636}]]
                            append Ko [binary format i [expr {$k ^ 0x5c5c5c5c}]]
                        }

                        # Calculate all codes valid within tolerance window
                        set totp_codes ""
                        # See "Stupid hack" below
                        set oformat "%0${totp_digits}d"
                        set time [expr [clock seconds] / $totp_period]
                        for { set o -$totp_tolerance } { $o <= $totp_tolerance } { incr o } {
                            # Calculate HMAC-SHA1(key, time)
                            set bintime [binary format W* [expr $time + $o]]
                            binary scan [$totp_algorithm $Ko[$totp_algorithm ${Ki}${bintime}]] H* token

                            # Derive TOTP code
                            set offset [expr ([scan [string index $token end] %x] & 0x0F) << 1]
                            # Stupid hack to workaround F5's TCL implementation lacking ** operator or pow() function
                            lappend totp_codes [format $oformat [expr (0x[string range $token $offset [expr $offset + 7]] & 0x7FFFFFFF) % [format "1${oformat}" 0]]]
                        }

                        if { [lsearch $totp_codes $totp_code] >= 0 } {
                            # Submitted code was a match, but was it replayed?
                            set table_key "${username}_${totp_code}"
                            if { [table lookup -notouch -subtable $totp_used_codes_table $table_key] != "" } {
                                # TOTP code matched on replay
                                set totp_result "code_reused"
                                set totp_message "TOTP verification failed: code reused, possible man-in-the-middle attack"
                            } else {
                                # TOTP code matched on first use
                                set totp_result "success"
                                set totp_message "TOTP verification succeeded"
                                # Record the successful use of this code to prevent replay
                                table set -subtable $totp_used_codes_table $table_key 1 [expr {$totp_period * $totp_tolerance * 2}]
                            }
                        } else {
                            # TOTP code didn't match
                            set totp_result "code_mismatch"
                            set totp_message "TOTP verification failed: code mismatch"
                        }
                    } else {
                        # TOTP key was invalid
                        set totp_result "invalid_key"
                        set totp_message "TOTP verification failed: invalid key found"
                    }
                } else {
                    # An empty TOTP code was submitted
                    set totp_result "no_code"
                    set totp_message "TOTP verification failed: no code"
                }
            } else {
                # TOTP lockout rate has been exceeded
                set totp_result "locked_out"
                set totp_message "TOTP verification failed: lockout rate exceeded; please wait ${totp_lockout_period} seconds"
            }
        
            # Set code verification result in session variable
            ACCESS::session data set session.custom.totp.result  $totp_result
            ACCESS::session data set session.custom.totp.message $totp_message
            # Set built-in OTP session variable for use with "OTP Result" conditionals
            ACCESS::session data set session.otp.verify.last.authresult [expr {($totp_result eq "success")?1:0}]
        }
    }
}