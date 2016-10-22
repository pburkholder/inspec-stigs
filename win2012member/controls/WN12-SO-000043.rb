# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000043 - The system must be configured to ignore NetBIOS name release requests except from WINS servers.'

control 'WN12-SO-000043' do
  impact 0.1
  title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc '
Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack.  The DoS consists of sending a NetBIOS name release request to the server for each entry in the server\'s cache, causing a response delay in the normal operation of the servers WINS resolution capability.
'
  tag 'stig','WN12-SO-000043'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000043_chk'
  tag fixid: 'F-WN12-SO-000043_fix'
  tag version: 'WN12-SO-000043'
  tag ruleid: 'WN12-SO-000043_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (NoNameReleaseOnDemand) Allow computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netbt\Parameters\

Value Name: NoNameReleaseOnDemand

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000043
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000043

end
