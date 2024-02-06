
app default {
	# debug = 0;
	# debug_file = "/tmp/latvia-eid.log";
	reader_driver pcsc {
		enable_pace = true;
	}
	framework pkcs15 {
		use_file_caching = false;
	}
}
	
app onepin-eidlv-pkcs11 {
	pkcs11 {
		slots_per_card = 1;
	}
}

# Used by EIDLV.tokend on Mac OS X only.
app tokend {
        # The file to which debug log will be written
        # Default: /tmp/EIDLV-tokend.log
        #
        # debug_file = /tmp/EIDLV-tokend.log

        framework tokend {
                # Score for EIDLV.tokend
                # The tokend with the highest score shall be used.
                # Default: 300
                #
                score = 1000;
        }
}

