tell application "System Events"
	if exists file "/usr/local/bin/latvia-eid-uninstall" then
		set result to do shell script "/usr/local/bin/latvia-eid-uninstall" with administrator privileges
		display alert "Removal complete" message result giving up after 10
	else
		display alert "Latvia-eID is not installed" message "Could not find /usr/local/bin/latvia-eid-uninstall" as critical giving up after 10
	end if
end tell