# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3472 - If the time service is configured, it must use an authorized time server.'
control 'V-3472' do
  impact 0.1
  title 'If the time service is configured, it must use an authorized time server.'
  desc 'The Windows Time Service controls time synchronization settings.  Time synchronization is essential for authentication and auditing purposes.  If the Windows Time Service is used, it must synchronize with a secure, authorized time source.   Domain-joined systems are automatically configured to synchronize with domain controllers.  If an NTP server is configured, it must synchronize with a secure, authorized time source.'
  tag 'stig', 'V-3472'
  tag severity: 'low'
  tag checkid: 'C-47224r3_chk'
  tag fixid: 'F-45845r1_fix'
  tag version: 'WN12-CC-000069'
  tag ruleid: 'SV-52919r2_rule'
  tag fixtext: 'If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration -> Administrative Templates -> System -> Windows Time Service -> Time Providers -> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.'
  tag checktext: 'Review the following registry values:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\W32time\Parameters\

Value Name: Type
Type: REG_SZ
Value: Possible values are NoSync, NTP, NT5DS, AllSync

and

Value Name: NTPServer
Type: REG_SZ
Value: "address of the time server"

If the following, this is a finding:
"Type" has a value of "NTP" or "Allsync" AND the "NTPServer" value is set to "time.windows.com" or other unauthorized server.

If the following, this not a finding:
The referenced registry values do not exist.
"Type" has a value of "NoSync" or "NT5DS".
"Type" has a value of "NTP" or "Allsync" AND the "NTPServer" is blank or configured to an authorized time server.

For DoD organizations, the US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy. 

Domain-joined systems are automatically configured to synchronize with domain controllers, and it would not be a finding unless this is changed.'

# START_DESCRIBE V-3472
  
    describe registry_key({
      name: 'Type',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\W32time\Parameters',
    }) do
      its("Type") { should eq Possible }
    end

# STOP_DESCRIBE V-3472

end

